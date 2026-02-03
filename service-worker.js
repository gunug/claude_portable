// Claude Portable Service Worker
const CACHE_NAME = 'claude-portable-v1';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icons/icon-72x72.png',
  '/icons/icon-96x96.png',
  '/icons/icon-128x128.png',
  '/icons/icon-144x144.png',
  '/icons/icon-152x152.png',
  '/icons/icon-192x192.png',
  '/icons/icon-384x384.png',
  '/icons/icon-512x512.png'
];

// 외부 리소스 (CDN)
const EXTERNAL_ASSETS = [
  'https://cdn.jsdelivr.net/npm/marked/marked.min.js'
];

// 설치 이벤트 - 정적 리소스 캐싱
self.addEventListener('install', (event) => {
  console.log('[ServiceWorker] 설치 중...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[ServiceWorker] 정적 리소스 캐싱');
        // 정적 리소스 캐싱 (실패해도 계속 진행)
        return Promise.allSettled([
          ...STATIC_ASSETS.map(url => cache.add(url).catch(() => console.log(`캐싱 실패: ${url}`))),
          ...EXTERNAL_ASSETS.map(url => cache.add(url).catch(() => console.log(`캐싱 실패: ${url}`)))
        ]);
      })
      .then(() => {
        console.log('[ServiceWorker] 설치 완료');
        return self.skipWaiting();
      })
  );
});

// 활성화 이벤트 - 오래된 캐시 정리
self.addEventListener('activate', (event) => {
  console.log('[ServiceWorker] 활성화 중...');
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME)
            .map((name) => {
              console.log('[ServiceWorker] 오래된 캐시 삭제:', name);
              return caches.delete(name);
            })
        );
      })
      .then(() => {
        console.log('[ServiceWorker] 활성화 완료');
        return self.clients.claim();
      })
  );
});

// Fetch 이벤트 - 네트워크 우선, 캐시 폴백
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // WebSocket 요청은 무시
  if (url.protocol === 'ws:' || url.protocol === 'wss:') {
    return;
  }

  // API 요청이나 WebSocket 업그레이드는 네트워크로
  if (event.request.url.includes('/ws') ||
      event.request.url.includes('/login') ||
      event.request.url.includes('/logout') ||
      event.request.headers.get('Upgrade') === 'websocket') {
    return;
  }

  event.respondWith(
    // 네트워크 우선 전략 (채팅 앱은 항상 최신 데이터 필요)
    fetch(event.request)
      .then((response) => {
        // 성공적인 응답은 캐시에 저장
        if (response.status === 200) {
          const responseClone = response.clone();
          caches.open(CACHE_NAME)
            .then((cache) => {
              cache.put(event.request, responseClone);
            });
        }
        return response;
      })
      .catch(() => {
        // 네트워크 실패 시 캐시에서 제공
        return caches.match(event.request)
          .then((response) => {
            if (response) {
              return response;
            }
            // 캐시에도 없으면 오프라인 페이지 표시
            if (event.request.mode === 'navigate') {
              return caches.match('/');
            }
            return new Response('오프라인 상태입니다.', {
              status: 503,
              statusText: 'Service Unavailable'
            });
          });
      })
  );
});

// 푸시 알림 수신 (향후 확장용)
self.addEventListener('push', (event) => {
  if (event.data) {
    const data = event.data.json();
    const options = {
      body: data.body || '새 메시지가 도착했습니다.',
      icon: '/icons/icon-192x192.png',
      badge: '/icons/icon-72x72.png',
      vibrate: [100, 50, 100],
      data: {
        url: data.url || '/'
      }
    };

    event.waitUntil(
      self.registration.showNotification(data.title || 'Claude Portable', options)
    );
  }
});

// 알림 클릭 처리
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then((clientList) => {
        // 이미 열린 창이 있으면 포커스
        for (const client of clientList) {
          if (client.url.includes(self.location.origin) && 'focus' in client) {
            return client.focus();
          }
        }
        // 없으면 새 창 열기
        if (clients.openWindow) {
          return clients.openWindow(event.notification.data.url || '/');
        }
      })
  );
});
