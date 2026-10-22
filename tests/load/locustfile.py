# SR-20: load test for the voting platform, using Locust.
# Start the app first (python app.py from the backend folder), then run this
# from the project folder:
#       locust -f tests/load/locustfile.py --headless -u 200 -r 20 -t 60s ^
#           --host http://127.0.0.1:5000 --html docs/load-test-report.html
#   -u 200   = 200 simulated terminals at once
#   -r 20    = start 20 new terminals every second
#   -t 60s   = run for 60 seconds
# (on Windows PowerShell use a backtick ` instead of ^ to continue the line)
#
# Or run `locust -f tests/load/locustfile.py` and open http://localhost:8089
# to start it from a web page with live graphs.
#
# The run counts as a fail (exit code 1) if more than 1% of requests fail or
# the slowest 5% of requests take longer than 1 second.
from locust import HttpUser, between, events, task

# CHECK: these are the pages that get hit. the first one should be the login page
LOGIN_PAGE = "/"
PUBLIC_KEY = "/api/admin/public-key"

MAX_FAIL_RATIO = 0.01  # 1% of requests may fail
MAX_P95_MS = 1000  # 95% of requests must finish within 1 second


class Terminal(HttpUser):
    # a voter at a terminal pauses 1-3 seconds between actions
    wait_time = between(1, 3)

    @task(3)
    def open_login_page(self):
        self.client.get(LOGIN_PAGE, name="login page")

    @task(1)
    def get_public_key(self):
        self.client.get(PUBLIC_KEY, name="public key")


@events.quitting.add_listener
def check_result(environment, **kwargs):
    # runs when the test ends and decides pass or fail
    stats = environment.stats.total
    p95 = stats.get_response_time_percentile(0.95)

    if stats.fail_ratio > MAX_FAIL_RATIO:
        print(f"LOAD TEST FAILED: {stats.fail_ratio:.1%} of requests failed")
        environment.process_exit_code = 1
    elif p95 > MAX_P95_MS:
        print(f"LOAD TEST FAILED: 95th percentile was {p95} ms (limit {MAX_P95_MS} ms)")
        environment.process_exit_code = 1
    else:
        print(f"LOAD TEST PASSED: {stats.fail_ratio:.1%} failed, 95th percentile {p95} ms")