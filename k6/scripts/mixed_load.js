import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const CONCURRENCY = parseInt(__ENV.CONCURRENCY || '50', 10);
const WARM_UP_S = parseInt(__ENV.WARM_UP_S || '30', 10);
const STEADY_STATE_S = parseInt(__ENV.STEADY_STATE_S || '60', 10);
const RAMP_DOWN_S = parseInt(__ENV.RAMP_DOWN_S || String(WARM_UP_S), 10);

export const options = {
  stages: [
    { duration: `${WARM_UP_S}s`, target: CONCURRENCY },
    { duration: `${STEADY_STATE_S}s`, target: CONCURRENCY },
    { duration: `${RAMP_DOWN_S}s`, target: 0 },
  ],
};

const BASE_URL = __ENV.BASE_URL || 'http://app.localhost';
const PROFILE = __ENV.PROFILE || 'profile-c';
const USERNAME = __ENV.USERNAME || 'testuser1';
const PASSWORD = __ENV.PASSWORD || 'password123';

const mixedLoadMs = new Trend('mixed_load_ms', true);
const profileErrors = new Rate('profile_error_rate');

export default function () {
  const started = Date.now();
  const selector = Math.random();
  let res;

  if (selector < 0.5) {
    res = http.get(`${BASE_URL}/`);
  } else if (selector < 0.8 && PROFILE === 'profile-c') {
    res = http.post(`${BASE_URL}/login/profile-c`, { username: USERNAME, password: PASSWORD }, { redirects: 0 });
  } else {
    res = http.get(`${BASE_URL}/login/${PROFILE}`, { redirects: 0 });
  }

  mixedLoadMs.add(Date.now() - started);
  const ok = check(res, {
    'mixed load request is accepted': (r) => r && (r.status === 200 || r.status === 302),
  });
  profileErrors.add(ok ? 0 : 1);
  sleep(0.5);
}

export function handleSummary(data) {
  if (!__ENV.SUMMARY_PATH) {
    return {};
  }
  return {
    [__ENV.SUMMARY_PATH]: JSON.stringify(data, null, 2),
  };
}
