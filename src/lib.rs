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
use anyhow::Result;
use chrono::prelude::*;
use defaultmap::DefaultHashMap;
use http::{Method, StatusCode};
use prettytable::{cell, Row, Table};
use std::cmp::Ordering;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::net::IpAddr;

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
    pub app_indexes: DefaultHashMap<u16, usize>,
    pub response_times: DefaultHashMap<usize, usize>,
    pub gorouter_times: DefaultHashMap<usize, usize>,
    pub x_cf_routererrors: DefaultHashMap<String, usize>,
}

impl TopInfo {
    pub fn new(max_results: usize, ignore_parse_errors: bool) -> TopInfo {
        TopInfo {
            max_results,
            ignore_parse_errors,
            duration: LogDuration {
                start: DateTime::default(),
                end: DateTime::default(),
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
            app_indexes: DefaultHashMap::new(0),
            response_times: DefaultHashMap::new(0),
            gorouter_times: DefaultHashMap::new(0),
            x_cf_routererrors: DefaultHashMap::new(0),
        }
    }

    pub fn process_file(&mut self, path: &str, log_type: access_log_parser::LogType) -> Result<()> {
        let tmp = io::stdin();
        let reader: io::BufReader<Box<dyn io::Read>> = if path.trim() == "-" {
            io::BufReader::new(Box::new(tmp.lock()))
        } else {
            io::BufReader::new(Box::new(fs::File::open(path)?))
        };

        reader
            .lines()
            .filter_map(|line| match line {
                Ok(line) => Some(line),
                Err(msg) => {
                    eprintln!("Read failed: {msg:#?}",);
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
                        eprintln!("Parse error: {err:#?} with line '{line}'");
                    }
                }
            });
        Ok(())
    }

    fn calc_stats(&mut self, log_entry: access_log_parser::LogEntry) {
        match log_entry {
            access_log_parser::LogEntry::CommonLog(log) => self.calc_common_log(log),
            access_log_parser::LogEntry::CombinedLog(log) => self.calc_combined_log(log),
            access_log_parser::LogEntry::GorouterLog(log) => self.calc_gorouter_log(log),
            access_log_parser::LogEntry::CloudControllerLog(log) => {
                self.calc_cloud_controller_log(log)
            }
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
        if let access_log_parser::RequestResult::Valid(ref req) = log_entry.request {
            self.request_methods[req.method().clone()] += 1;
        }
        self.client_ips[log_entry.ip] += 1;

        // count query path hits
        let (path, path_no_query) = match log_entry.request {
            access_log_parser::RequestResult::Valid(ref req) => (
                req.uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("<none>"),
                req.uri().path(),
            ),
            access_log_parser::RequestResult::InvalidPath(path, _err) => (path, ""),
            access_log_parser::RequestResult::InvalidRequest(path) => (path, ""),
        };
        self.requests_no_query[path_no_query.to_string()] += 1;
        self.requests_query[path.to_string()] += 1;
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
        if let access_log_parser::RequestResult::Valid(ref req) = log_entry.request {
            self.request_methods[req.method().clone()] += 1;
        }
        self.client_ips[log_entry.ip] += 1;

        // count query path hits
        let (path, path_no_query) = match log_entry.request {
            access_log_parser::RequestResult::Valid(ref req) => (
                req.uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("<none>"),
                req.uri().path(),
            ),
            access_log_parser::RequestResult::InvalidPath(path, _err) => (path, ""),
            access_log_parser::RequestResult::InvalidRequest(path) => (path, ""),
        };
        self.requests_no_query[path_no_query.to_string()] += 1;
        self.requests_query[path.to_string()] += 1;

        // count referrer hits
        if let Some(referrer) = log_entry.referrer {
            self.referrers[referrer] += 1;
        }

        // count user agent hits
        self.user_agents[log_entry.user_agent.unwrap_or("<none>").to_string()] += 1;
    }

    fn calc_cloud_controller_log(&mut self, log_entry: access_log_parser::CloudControllerLogEntry) {
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
        if let access_log_parser::RequestResult::Valid(ref req) = log_entry.request {
            self.request_methods[req.method().clone()] += 1;
        }

        // count query path hits
        let (path, path_no_query) = match log_entry.request {
            access_log_parser::RequestResult::Valid(ref req) => (
                req.uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("<none>"),
                req.uri().path(),
            ),
            access_log_parser::RequestResult::InvalidPath(path, _err) => (path, ""),
            access_log_parser::RequestResult::InvalidRequest(path) => (path, ""),
        };
        self.requests_no_query[path_no_query.to_string()] += 1;
        self.requests_query[path.to_string()] += 1;

        // count referrer hits
        if let Some(referrer) = log_entry.referrer {
            self.referrers[referrer] += 1;
        }

        // count user agent hits
        self.user_agents[log_entry.user_agent.unwrap_or("<none>").to_string()] += 1;

        // count cloud controller specific hits
        self.x_forwarded_fors[log_entry
            .x_forwarded_for
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .join(", ")] += 1;
        self.hosts[log_entry.request_host.into()] += 1;

        // bucket response times
        self.response_times[log_entry
            .response_time
            .map(|t| t.floor() as usize)
            .unwrap_or(usize::max_value())] += 1;
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
        if let access_log_parser::RequestResult::Valid(ref req) = log_entry.request {
            self.request_methods[req.method().clone()] += 1;
        }
        self.client_ips[log_entry.remote_addr] += 1;

        // count query path hits
        let (path, path_no_query) = match log_entry.request {
            access_log_parser::RequestResult::Valid(ref req) => (
                req.uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("<none>"),
                req.uri().path(),
            ),
            access_log_parser::RequestResult::InvalidPath(path, _err) => (path, ""),
            access_log_parser::RequestResult::InvalidRequest(path) => (path, ""),
        };
        self.requests_no_query[path_no_query.to_string()] += 1;
        self.requests_query[path.to_string()] += 1;

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
        if let Some(app_index) = log_entry.app_index {
            self.app_indexes[app_index] += 1;
        }

        // bucket response times
        self.response_times[log_entry
            .response_time
            .map(|t| t.floor() as usize)
            .unwrap_or(usize::max_value())] += 1;

        // bucket gorouter times
        self.gorouter_times[log_entry
            .gorouter_time
            .map(|t| t.floor() as usize)
            .unwrap_or(usize::max_value())] += 1;

        // count x_cf_routererror hits
        self.x_cf_routererrors[log_entry.x_cf_routererror.unwrap_or("<none>").to_string()] += 1;
    }

    fn print_map<I, K, V>(iter: I, sort_order: &SortOrder, max: usize)
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

    pub fn print_summary(&self, min_response_time_threshold: usize) {
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

        if !self.user_agents.is_empty() {
            println!("Top '{}' User Agents", self.max_results);
            TopInfo::print_map(
                self.user_agents.iter(),
                &SortOrder::ByValue,
                self.max_results,
            );
        }

        if !self.referrers.is_empty() {
            println!("Top '{}' Referrers", self.max_results);
            TopInfo::print_map(self.referrers.iter(), &SortOrder::ByValue, self.max_results);
        }

        if !self.client_ips.is_empty() {
            println!("Top '{}' Client IPs", self.max_results);
            TopInfo::print_map(
                self.client_ips.iter(),
                &SortOrder::ByValue,
                self.max_results,
            );
        }

        if !self.backend_ips.is_empty() {
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

        if !self.x_forwarded_fors.is_empty() {
            println!("Top '{}' X-Forwarded-For Ips", self.max_results);
            TopInfo::print_map(
                self.x_forwarded_fors.iter(),
                &SortOrder::ByValue,
                self.max_results,
            );
        }

        if !self.hosts.is_empty() {
            println!("Top '{}' Destination Hosts", self.max_results);
            TopInfo::print_map(self.hosts.iter(), &SortOrder::ByValue, self.max_results);
        }

        if !self.app_ids.is_empty() {
            println!("Top '{}' Application UUIDs", self.max_results);
            TopInfo::print_map(self.app_ids.iter(), &SortOrder::ByValue, self.max_results);
        }

        if !self.app_indexes.is_empty() {
            println!("Top '{}' Application Indexes", self.max_results);
            TopInfo::print_map(
                self.app_indexes.iter(),
                &SortOrder::ByValue,
                self.max_results,
            );
        }

        if !self.response_times.is_empty() {
            println!("Top Response Times");
            let mut keys: Vec<&usize> = self
                .response_times
                .keys()
                .filter(|&k| *k < usize::max_value())
                .collect();
            keys.sort();

            let max_key = **keys.iter().max().unwrap_or(&&0);
            let max_width = format!("{max_key}").len();

            println!();

            let mut table = Table::new();
            table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP);

            let mut bucket_val: usize = 0;
            let mut bucket_start: usize = 0;

            for key in keys {
                if bucket_start == 0 {
                    bucket_start = *key;
                }

                bucket_val += self.response_times[key];

                if bucket_val >= min_response_time_threshold {
                    table.add_row(Row::new(vec![
                        cell!(format!(
                            "{:width$} to {:width$}",
                            bucket_start,
                            key + 1,
                            width = max_width
                        )),
                        cell!(bucket_val),
                    ]));
                    bucket_start = 0;
                    bucket_val = 0;
                }
            }

            if bucket_val > 0 {
                table.add_row(Row::new(vec![
                    cell!(format!(
                        "{:width$} to {:width$}",
                        bucket_start,
                        max_key + 1,
                        width = max_width
                    )),
                    cell!(bucket_val),
                ]));
            }

            if self.response_times.contains_key(&usize::max_value()) {
                table.add_row(Row::new(vec![
                    cell!("<none>"),
                    cell!(self.response_times.get(usize::max_value())),
                ]));
            }

            table.printstd();

            println!();
        }

        if !self.gorouter_times.is_empty() {
            println!("Top Gorouter Times");
            let mut keys: Vec<&usize> = self
                .gorouter_times
                .keys()
                .filter(|&k| *k < usize::max_value())
                .collect();
            keys.sort();

            let max_key = **keys.iter().max().unwrap_or(&&0);
            let max_width = format!("{max_key}").len();

            println!();

            let mut table = Table::new();
            table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP);

            let mut bucket_val: usize = 0;
            let mut bucket_start: usize = 0;

            for key in keys {
                if bucket_start == 0 {
                    bucket_start = *key;
                }

                bucket_val += self.gorouter_times[key];

                if bucket_val >= min_response_time_threshold {
                    table.add_row(Row::new(vec![
                        cell!(format!(
                            "{:width$} to {:width$}",
                            bucket_start,
                            key + 1,
                            width = max_width
                        )),
                        cell!(bucket_val),
                    ]));
                    bucket_start = 0;
                    bucket_val = 0;
                }
            }

            if bucket_val > 0 {
                table.add_row(Row::new(vec![
                    cell!(format!(
                        "{:width$} to {:width$}",
                        bucket_start,
                        max_key + 1,
                        width = max_width
                    )),
                    cell!(bucket_val),
                ]));
            }

            if self.gorouter_times.contains_key(&usize::max_value()) {
                table.add_row(Row::new(vec![
                    cell!("<none>"),
                    cell!(self.gorouter_times.get(usize::max_value())),
                ]));
            }

            table.printstd();

            println!();
        }

        if !self.x_cf_routererrors.is_empty() {
            println!("Top '{}' CF Router Errors", self.max_results);
            TopInfo::print_map(
                self.x_cf_routererrors.iter(),
                &SortOrder::ByValue,
                self.max_results,
            );
        }
    }
}
