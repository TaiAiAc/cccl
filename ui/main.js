(function () {
  'use strict';

  var stage = document.getElementById('stage');
  var light = document.getElementById('light');

  var tauri = window.__TAURI__ || {};
  var invoke = tauri.core && tauri.core.invoke;
  var listen = tauri.event && tauri.event.listen;
  var currentWindow =
    tauri.window && tauri.window.getCurrentWindow
      ? tauri.window.getCurrentWindow()
      : null;

  var KNOWN = ['checking', 'ok', 'warn', 'bad', 'cut'];
  var lastState = '';

  function render(payload) {
    payload = payload || {};
    var state = KNOWN.indexOf(payload.state) >= 0 ? payload.state : 'checking';
    if (state !== lastState) {
      stage.className = 'state-' + state;
      lastState = state;
    }
    if (payload.label) {
      var tip = 'ClaudeBall · ' + payload.label;
      if (payload.detail) tip += '\n' + payload.detail;
      if (payload.exit_ip) tip += '\n' + payload.exit_ip;
      if (payload.protected === false) tip += '\n封锁保护已关闭（托盘菜单里重新勾选）';
      document.title = tip;
      light.title = tip;
    }
  }

  // ---- 拖动 / 点击 ----
  var press = null;
  var dragging = false;

  function checkNow() {
    if (invoke) {
      invoke('check_now').catch(function () {});
    }
  }

  light.addEventListener('mousedown', function (e) {
    if (e.button !== 0) return;
    press = { x: e.screenX, y: e.screenY };
    dragging = false;
  });

  window.addEventListener('mousemove', function (e) {
    if (!press || dragging) return;
    var dx = e.screenX - press.x;
    var dy = e.screenY - press.y;
    if (Math.sqrt(dx * dx + dy * dy) <= 4) return;

    dragging = true;
    document.body.classList.add('dragging');
    if (currentWindow) {
      currentWindow
        .startDragging()
        .catch(function () {})
        .then(function () {
          document.body.classList.remove('dragging');
          press = null;
          dragging = false;
        });
    }
  });

  window.addEventListener('mouseup', function () {
    var wasClick = press && !dragging;
    press = null;
    dragging = false;
    document.body.classList.remove('dragging');
    if (wasClick) checkNow();
  });

  window.addEventListener('contextmenu', function (e) {
    e.preventDefault();
  });

  // ---- 跟后端对接 ----
  if (listen) {
    listen('status', function (event) {
      render(event.payload);
    });
    listen('log', function (event) {
      console.log('[ClaudeBall]', event.payload);
    });
    listen('cut', function (event) {
      console.warn('[ClaudeBall] 已切断 Claude 联网：', event.payload);
    });
  }

  if (invoke) {
    invoke('get_status')
      .then(render)
      .catch(function () {});
  } else {
    // 直接在浏览器里打开时用来看样式
    render({ state: 'ok', label: '预览模式' });
  }
})();
