(function () {
  'use strict';

  let SUCCESS_HANDLERS = [];
  let ERROR_HANDLERS = [];

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/ui/sw.js', {
      scope: '/v1/sys/storage/raft/snapshot'
    }).then(function (reg) {
      let current = Promise.resolve();

      for (let i = 0, len = SUCCESS_HANDLERS.length; i < len; i++) {
        current = current.then(function () {
          return SUCCESS_HANDLERS[i](reg);
        });
      }

      return current.then(function () {
        console.log('Service Worker registration succeeded. Scope is ' + reg.scope);
      });
    }).catch(function (error) {
      let current = Promise.resolve();

      for (let i = 0, len = ERROR_HANDLERS.length; i < len; i++) {
        current = current.then(function () {
          return ERROR_HANDLERS[i](error);
        });
      }

      return current.then(function () {
        console.log('Service Worker registration failed with ' + error);
      });
    });
  }

  function addSuccessHandler(func) {
    SUCCESS_HANDLERS.push(func);
  }

  /**
   * Copyright (c) HashiCorp, Inc.
   * SPDX-License-Identifier: MPL-2.0
   */
  addSuccessHandler(function (registration) {
    // attempt to unregister the service worker on unload because we're not doing any sort of caching
    window.addEventListener('unload', function () {
      registration.unregister();
    });
  });

}());
