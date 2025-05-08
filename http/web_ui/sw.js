(function () {
  'use strict';

  const VERSION = '1742317176189|0.6736860860624643';
  self.CACHE_BUSTER = VERSION;
  self.addEventListener('install', function installEventListenerCallback(event) {
    return self.skipWaiting();
  });
  self.addEventListener('message', function skipWaitingMessageCallback(event) {
    if (event.data === 'skipWaiting') {
      return self.skipWaiting();
    }
  });
  self.addEventListener('activate', function installEventListenerCallback(event) {
    return self.clients.claim();
  });

  /**
   * Create an absolute URL, allowing regex expressions to pass
   *
   * @param {string} url
   * @param {string|object} baseUrl
   * @public
   */
  function createNormalizedUrl(url) {
    let baseUrl = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : self.location;
    return decodeURI(new URL(encodeURI(url), baseUrl).toString());
  }
  /**
   * Create an (absolute) URL Regex from a given string
   *
   * @param {string} url
   * @returns {RegExp}
   * @public
   */

  function createUrlRegEx(url) {
    let normalized = createNormalizedUrl(url);
    return new RegExp(`^${normalized}$`);
  }
  /**
   * Check if given URL matches any pattern
   *
   * @param {string} url
   * @param {array} patterns
   * @returns {boolean}
   * @public
   */

  function urlMatchesAnyPattern(url, patterns) {
    return !!patterns.find(pattern => pattern.test(decodeURI(url)));
  }

  /**
   * Copyright (c) HashiCorp, Inc.
   * SPDX-License-Identifier: MPL-2.0
   */
  var patterns = ['/v1/sys/storage/raft/snapshot'];
  var REGEXES = patterns.map(createUrlRegEx);

  function sendMessage(message) {
    return self.clients.matchAll({
      includeUncontrolled: true,
      type: 'window'
    }).then(function (results) {
      var client = results[0];
      return new Promise(function (resolve, reject) {
        var messageChannel = new MessageChannel();

        messageChannel.port2.onmessage = function (event) {
          if (event.data.error) {
            reject(event.data.error);
          } else {
            resolve(event.data.token);
          }
        };

        client.postMessage(message, [messageChannel.port1]);
      });
    });
  }

  function authenticateRequest(request) {
    // copy the reaquest headers so we can mutate them
    const headers = new Headers(request.headers); // get and set vault token so the request is authenticated

    return sendMessage({
      action: 'getToken'
    }).then(function (token) {
      headers.set('X-Vault-Token', token); // continue the fetch with the new request
      // that has the auth header

      return fetch(new Request(request.url, {
        method: request.method,
        headers
      }));
    });
  }

  self.addEventListener('fetch', function (fetchEvent) {
    const request = fetchEvent.request;

    if (urlMatchesAnyPattern(request.url, REGEXES) && request.method === 'GET') {
      return fetchEvent.respondWith(authenticateRequest(request));
    } else {
      return fetchEvent.respondWith(fetch(request));
    }
  });

}());
