// Copyright 2019 Daniel Mikusa

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use access_log_parser;
use chrono::prelude::*;
use clap::{crate_version, value_t, App, Arg};
use defaultmap::DefaultHashMap;
use http::{Method, StatusCode};
use prettytable::{cell, Row, Table};
use std::cmp::Ordering;
use std::f32;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::net::IpAddr;

fn main() {
    let matches = App::new("top-logs")
                    .version(crate_version!())
                    .author("Daniel Mikusa <dmikusa@pivotal.io>")
                    .about("Parses various access log formats and prints stats helpful for debugging/troubleshooting.")
                    .arg(Arg::with_name("top")
                            .short("t")
                            .long("top")
                            .value_name("NUM")
                            .default_value("10")
                            .help("number of results to display")
                            .takes_value(true))
                    .arg(Arg::with_name("format")
                            .short("f")
                            .long("format")
                            .value_name("LOG_FORMAT")
                            .required(true)
                            .help("access log format")
                            .takes_value(true)
                            .possible_values(&["common", "combined", "gorouter", "cloud_controller"]))
                    .arg(Arg::with_name("ignore_parse_errors")
                            .short("i")
                            .long("ignore-parse-errors")
                            .help("Don't log any parsing error"))
                    .arg(Arg::with_name("access_logs")
                            .value_name("ACCESS_LOG")
                            .help("Access logs to process")
                            .index(1)
                            .multiple(true)
                            .takes_value(true))
                    .get_matches();

    let mut ti = TopInfo::new(
        value_t!(matches, "top", usize).unwrap(),
        matches.is_present("ignore_parse_errors"),
    );

    for file in matches.values_of("access_logs").unwrap() {
        match ti.process_file(
            file,
            value_t!(matches, "format", access_log_parser::LogType).unwrap(),
        ) {
            Ok(()) => (),
            Err(msg) => eprintln!("Failed parsing file: {}, message: {}", file, msg),
        }
    }

    ti.print_summary();
}

pub enum SortOrder {
    ByValue,
    ByKey,
}

impl SortOrder {
    pub fn sort_by_val<K, V>(a: &(K, V), b: &(K, V)) -> Ordering
    where
        V: Ord,
    {
        b.1.cmp(&a.1)
    }

    pub fn sort_by_key<K, V>(a: &(K, V), b: &(K, V)) -> Ordering
    where
        K: ToString,
    {
        a.0.to_string().cmp(&b.0.to_string())
    }
}

#[derive(Debug)]
pub struct LogDuration {
    pub start: DateTime<FixedOffset>,
    pub end: DateTime<FixedOffset>,
}

#[derive(Debug)]
pub struct TopInfo {
    max_results: usize,
    ignore_parse_errors: bool,
    pub duration: LogDuration,
    pub total_requests: usize,
    pub errors: usize,
    pub response_codes: DefaultHashMap<StatusCode, usize>,
    pub request_methods: DefaultHashMap<Method, usize>,
    pub requests_no_query: DefaultHashMap<String, usize>,
    pub requests_query: DefaultHashMap<String, usize>,
    pub client_ips: DefaultHashMap<IpAddr, usize>,
    pub referrers: DefaultHashMap<http::Uri, usize>,
    pub user_agents: DefaultHashMap<String, usize>,
    pub backend_ips: DefaultHashMap<IpAddr, usize>,
    pub x_forwarded_fors: DefaultHashMap<String, usize>,
    pub hosts: DefaultHashMap<String, usize>,
    pub app_ids: DefaultHashMap<String, usize>,
    pub response_times: Vec<((f32, f32), usize)>,
}

impl TopInfo {
    pub fn new(max_results: usize, ignore_parse_errors: bool) -> TopInfo {
        let mut response_times = Vec::with_capacity(10);
        response_times.push(((0.0, 1.0), 0));
        response_times.push(((1.0, 2.0), 0));
        response_times.push(((2.0, 3.0), 0));
        response_times.push(((3.0, 4.0), 0));
        response_times.push(((4.0, 5.0), 0));
        response_times.push(((5.0, 7.0), 0));
        response_times.push(((7.0, 10.0), 0));
        response_times.push(((10.0, 15.0), 0));
        response_times.push(((15.0, 20.0), 0));
        response_times.push(((20.0, f32::MAX), 0));

        TopInfo {
            max_results: max_results,
            ignore_parse_errors: ignore_parse_errors,
            duration: LogDuration {
                start: FixedOffset::west(5 * 3600)
                    .ymd(9999, 12, 31)
                    .and_hms(23, 59, 59),
                end: FixedOffset::west(5 * 3600).ymd(0, 1, 1).and_hms(0, 0, 0),
            },
            total_requests: 0,
            errors: 0,
            response_codes: DefaultHashMap::new(0),
            request_methods: DefaultHashMap::new(0),
            requests_no_query: DefaultHashMap::new(0),
            requests_query: DefaultHashMap::new(0),
            client_ips: DefaultHashMap::new(0),
            referrers: DefaultHashMap::new(0),
            user_agents: DefaultHashMap::new(0),
            backend_ips: DefaultHashMap::new(0),
            x_forwarded_fors: DefaultHashMap::new(0),
            hosts: DefaultHashMap::new(0),
            app_ids: DefaultHashMap::new(0),
            response_times: response_times,
        }
    }

    pub fn process_file(
        &mut self,
        path: &str,
        log_type: access_log_parser::LogType,
    ) -> io::Result<()> {
        let reader = io::BufReader::new(fs::File::open(path)?);

        Ok(reader
            .lines()
            .filter_map(|line| match line {
                Ok(line) => Some(line),
                Err(msg) => {
                    eprintln!("Read failed: {:#?}", msg);
                    None
                }
            })
            .for_each(|line| match access_log_parser::parse(log_type, &line) {
                Ok(log) => {
                    self.calc_stats(log);
                }
                Err(err) => {
                    self.errors += 1;
                    if !self.ignore_parse_errors {
                        eprintln!("Parse error: {:#?} with line '{}'", err, line);
                    }
                }
            }))
    }

    fn calc_stats(&mut self, log_entry: access_log_parser::LogEntry) {
        match log_entry {
            access_log_parser::LogEntry::CommonLog(log) => self.calc_common_log(log),
            access_log_parser::LogEntry::CombinedLog(log) => self.calc_combined_log(log),
            access_log_parser::LogEntry::GorouterLog(log) => self.calc_gorouter_log(log),
        }
    }

    fn calc_common_log(&mut self, log_entry: access_log_parser::CommonLogEntry) {
        // count total requests
        self.total_requests += 1;

        // pick out oldest & newest log entries
        if log_entry.timestamp < self.duration.start {
            self.duration.start = log_entry.timestamp;
        }
        if log_entry.timestamp > self.duration.end {
            self.duration.end = log_entry.timestamp;
        }

        // count individual resources
        self.response_codes[log_entry.status_code] += 1;
        self.request_methods[log_entry.request.method().clone()] += 1;
        self.client_ips[log_entry.ip] += 1;

        // count query path hits
        if let Some(path) = log_entry.request.uri().path_and_query() {
            self.requests_no_query[path.path().into()] += 1;
            self.requests_query[path.as_str().into()] += 1;
        } else {
            // if path doesn't exist, then we still want to count that
            self.requests_no_query["<none>".to_string()] += 1;
            self.requests_query["<none>".to_string()] += 1;
        }
    }

    fn calc_combined_log(&mut self, log_entry: access_log_parser::CombinedLogEntry) {
        // count total requests
        self.total_requests += 1;

        // pick out oldest & newest log entries
        if log_entry.timestamp < self.duration.start {
            self.duration.start = log_entry.timestamp;
        }
        if log_entry.timestamp > self.duration.end {
            self.duration.end = log_entry.timestamp;
        }

        // count individual resources
        self.response_codes[log_entry.status_code] += 1;
        self.request_methods[log_entry.request.method().clone()] += 1;
        self.client_ips[log_entry.ip] += 1;

        // count query path hits
        if let Some(path) = log_entry.request.uri().path_and_query() {
            self.requests_no_query[path.path().into()] += 1;
            self.requests_query[path.as_str().into()] += 1;
        } else {
            // if path doesn't exist, then we still want to count that
            self.requests_no_query["<none>".to_string()] += 1;
            self.requests_query["<none>".to_string()] += 1;
        }

        // count referrer hits
        if let Some(referrer) = log_entry.referrer {
            self.referrers[referrer] += 1;
        }

        // count user agent hits
        self.user_agents[log_entry.user_agent.unwrap_or("<none>").to_string()] += 1;
    }

    fn calc_gorouter_log(&mut self, log_entry: access_log_parser::GorouterLogEntry) {
        // count total requests
        self.total_requests += 1;

        // pick out oldest & newest log entries
        if log_entry.timestamp < self.duration.start {
            self.duration.start = log_entry.timestamp;
        }
        if log_entry.timestamp > self.duration.end {
            self.duration.end = log_entry.timestamp;
        }

        // count individual resources
        self.response_codes[log_entry.status_code] += 1;
        self.request_methods[log_entry.request.method().clone()] += 1;
        self.client_ips[log_entry.remote_addr] += 1;

        // count query path hits
        if let Some(path) = log_entry.request.uri().path_and_query() {
            self.requests_no_query[path.path().into()] += 1;
            self.requests_query[path.as_str().into()] += 1;
        } else {
            // if path doesn't exist, then we still want to count that
            self.requests_no_query["<none>".to_string()] += 1;
            self.requests_query["<none>".to_string()] += 1;
        }

        // count referrer hits
        if let Some(referrer) = log_entry.referrer {
            self.referrers[referrer] += 1;
        }

        // count user agent hits
        self.user_agents[log_entry.user_agent.unwrap_or("<none>").to_string()] += 1;

        // count gorouter specific hits
        if let Some(ip) = log_entry.backend_addr {
            self.backend_ips[ip] += 1;
        }
        self.x_forwarded_fors[log_entry
            .x_forwarded_for
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .join(", ")] += 1;
        self.hosts[log_entry.request_host.into()] += 1;
        if let Some(app_id) = log_entry.app_id {
            self.app_ids[app_id.into()] += 1;
        }

        // bucket response times
        let response_time = log_entry.response_time;
        for (range, cnt) in self.response_times.iter_mut() {
            if response_time > range.0 && response_time < range.1 {
                *cnt += 1;
            }
        }
    }

    fn print_map<'a, I, K, V>(iter: I, sort_order: &SortOrder, max: usize)
    where
        K: ToString,
        V: Ord + ToString,
        I: Iterator<Item = (K, V)>,
    {
        let mut data: Vec<(K, V)> = iter.collect();

        match sort_order {
            SortOrder::ByKey => data.sort_by(SortOrder::sort_by_key),
            SortOrder::ByValue => data.sort_by(SortOrder::sort_by_val),
        };

        println!();

        let mut table = Table::new();
        table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP);
        for (key, val) in data.iter().take(max) {
            table.add_row(Row::new(vec![cell!(key), cell!(val)]));
        }
        table.printstd();

        println!();
    }

    pub fn print_summary(&self) {
        println!();
        println!("Duration: {} to {}", self.duration.start, self.duration.end);
        println!();

        println!();
        println!("Total Requests: {}", self.total_requests);
        println!("Total Errors  : {}", self.errors);
        println!();

        println!("Response Codes:");
        TopInfo::print_map(
            self.response_codes.iter(),
            &SortOrder::ByKey,
            usize::max_value(),
        );

        println!("Request Methods:");
        TopInfo::print_map(
            self.request_methods.iter(),
            &SortOrder::ByValue,
            usize::max_value(),
        );

        println!("Top '{}' Requests (no query params)", self.max_results);
        TopInfo::print_map(
            self.requests_no_query.iter(),
            &SortOrder::ByValue,
            self.max_results,
        );

        println!("Top '{}' Requests (with query params)", self.max_results);
        TopInfo::print_map(
            self.requests_query.iter(),
            &SortOrder::ByValue,
            self.max_results,
        );

        if self.user_agents.len() > 0 {
            println!("Top '{}' User Agents", self.max_results);
            TopInfo::print_map(
                self.user_agents.iter(),
                &SortOrder::ByValue,
                self.max_results,
            );
        }

        if self.referrers.len() > 0 {
            println!("Top '{}' Referrers", self.max_results);
            TopInfo::print_map(self.referrers.iter(), &SortOrder::ByValue, self.max_results);
        }

        if self.client_ips.len() > 0 {
            println!("Top '{}' Client IPs", self.max_results);
            TopInfo::print_map(
                self.client_ips.iter(),
                &SortOrder::ByValue,
                self.max_results,
            );
        }

        if self.backend_ips.len() > 0 {
            println!(
                "Top '{}' Backend Address (Cells & Platform VMs)",
                self.max_results
            );
            TopInfo::print_map(
                self.backend_ips.iter(),
                &SortOrder::ByValue,
                self.max_results,
            );
        }

        if self.x_forwarded_fors.len() > 0 {
            println!("Top '{}' X-Forwarded-For Ips", self.max_results);
            TopInfo::print_map(
                self.x_forwarded_fors.iter(),
                &SortOrder::ByValue,
                self.max_results,
            );
        }

        if self.hosts.len() > 0 {
            println!("Top '{}' Destination Hosts", self.max_results);
            TopInfo::print_map(self.hosts.iter(), &SortOrder::ByValue, self.max_results);
        }

        if self.app_ids.len() > 0 {
            println!("Top '{}' Application UUIDs", self.max_results);
            TopInfo::print_map(self.app_ids.iter(), &SortOrder::ByValue, self.max_results);
        }

        if self.response_times.len() > 0 {
            println!("Top Response Times");
            TopInfo::print_map(
                self.response_times.iter().map(|(k, v)| {
                    (
                        if k.1 == f32::MAX {
                            format!("{:2} to MAX", k.0)
                        } else {
                            format!("{:2} to {}", k.0, k.1)
                        },
                        v,
                    )
                }),
                &SortOrder::ByKey,
                self.max_results,
            );
        }
    }
}
