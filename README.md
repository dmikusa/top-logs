# Top Logs

Tops logs is a tool which can be used to parse through access logs to understand usage trends and hunt for problems. It generates reports that shows top X (where X is a number that defaults to 10) lists of different metrics, like request queries, user agents, response times, etc.

## Features

* Supported log formats:
  - Common
  - Combined
  - Gorouter
  - Cloud Controller

* Read access logs and report the following metrics:
  - Common
    - Duration of logs (oldest and newest log dates)
    - Total number of requests
    - Total number of requests the tool didn't understand/couldn't parse
    - Top X Response Codes
    - Top X Request Methods
    - Top X Requests (no query params)
    - Top X Requests (with query params)
  - Combined
    - Duration of logs (oldest and newest log dates)
    - Total number of requests
    - Total number of requests the tool didn't understand/couldn't parse
    - Top X Response Codes
    - Top X Request Methods
    - Top X Requests (no query params)
    - Top X Requests (with query params)
    - Top X User Agents
    - Top X Referrers
    - Top X Client IPs
  - Cloud Controller
    - Duration of logs (oldest and newest log dates)
    - Total number of requests
    - Total number of requests the tool didn't understand/couldn't parse
    - Top X Response Codes
    - Top X Request Methods
    - Top X Requests (no query params)
    - Top X Requests (with query params)
    - Top X User Agents
    - Top X Referrers
    - Top X X-Forwarded-For Ips
    - Response time histogram
  - Gorouter
    - Duration of logs (oldest and newest log dates)
    - Total number of requests
    - Total number of requests the tool didn't understand/couldn't parse
    - Top X Response Codes
    - Top X Request Methods
    - Top X Requests (no query params)
    - Top X Requests (with query params)
    - Top X User Agents
    - Top X Referrers
    - Top X Client IPs
    - Top X X-Forwarded-For Ips
    - Response time histogram
    - Gorouter time histogram
    - Top X Backend Address (Cells & Platform VMs)
    - Top X Destination Hosts
    - Top X App GUIDs
    - Top X x_cf_routererror responses

## Usage

```
$ ./target/release/top-logs -i -f cloud_controller data/cloud_controller/nginx.access.log* -h
top-logs 1.3.0
Daniel Mikusa <dmikusa@pivotal.io>
Parses various access log formats and prints stats helpful for debugging/troubleshooting.

USAGE:
    top-logs [FLAGS] [OPTIONS] --format <LOG_FORMAT> [ACCESS_LOG]...

FLAGS:
    -h, --help                   Prints help information
    -i, --ignore-parse-errors    Don't log any parsing error
    -V, --version                Prints version information

OPTIONS:
    -f, --format <LOG_FORMAT>
            access log format [possible values: common, combined, gorouter, cloud_controller]

    -m, --min-response-time-threshold <MIN_THRESHOLD>
            Minimum threshold in number of requests for a response time bucket to be displayed. Smaller buckets are
            grouped together. [default: 100]
    -t, --top <NUM>                                      number of results to display [default: 10]

ARGS:
    <ACCESS_LOG>...    Access logs to process
```

## Tips

- If the tool cannot parse a log line, it will print that log line & where parsing failed to STDERR. If you have a lot of log lines that are bad/cannot be parsed this can be annoying. You can use the `-i` option to supress these or you can `>/dev/null` on Unix systems.

- To drill down into a particular subset of logs, the `grep` tool is very handy. Let's say you run `top-logs` and see that there are may requests coming from a specific user agent & you want to know more about just those requests. You can `grep <user-agent> access.log > user-agent-access.log` and then run `top-logs` on just that subset of logs. This is great for drilling into other things like slow requests, request hotspots and app/host hotspots.

## License

This software is released under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
