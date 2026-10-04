import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  timeout: 45_000,
  use: { baseURL: 'http://127.0.0.1:8001', trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop', use: { viewport: { width: 1440, height: 1000 } } },
    { name: 'mobile', use: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
  ],
  webServer: {
    command: 'SECURENET_RECEIVER_PORT=9001 SECURENET_DATA_DIR=../.data/browser-tests SECURENET_KEYS_DIR=../.data/browser-tests/keys SECURENET_PASSWORD_FILE=../.data/browser-tests/password ../.venv/bin/python -m uvicorn securenet.api:app --host 127.0.0.1 --port 8001 --no-access-log',
    url: 'http://127.0.0.1:8001/api/health',
    reuseExistingServer: false,
  },
});
