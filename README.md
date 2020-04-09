## Overview

A collection of static files maintained by the Sublime team, primarily used for phishing defense.

## Repo contents

* `alexa_top_1m.csv`: [Alexa](https://www.alexa.com/topsites) top 1 million sites.
* `disposable_email_providers.txt`: Disposable (or temporary) email providers that generate short-lived email addresses not owned by or attributable to any single user.
* `free_email_providers.txt`: Free email ("freemail") providers that allow anyone to create an email address. This is important to ensure the email address does not inherit the reputation of the freemail provider's domain. This list also includes the contents of the `disposable_email_providers.txt` list.
* `free_file_hosts.txt`: Free file hosting sites that allow anyone to upload and serve arbitrary files.
* `free_subdomain_hosts.txt`: Free subdomain sites that allow anyone to create their own subdomain and host arbitrary content. This is important to ensure the subdomains do not inherit the reputation of the root domain. 
* `majestic_million.csv`: [Majestic million](https://majestic.com/reports/majestic-million) is a collection of domains that have the most referring subnets.
* `suspicious_content.txt`: Words or phrases that may be considered suspicious in an email body.
* `suspicious_subjects.txt`: Words or phrases that may be considered suspicious in an email subject.
* `suspicious_subjects_regex.txt`: Regular expressions for words or phrases that may be considered suspicious in an email subject.
* `suspicious_tlds.txt`: Top-level domains that are either frequently abused, free to register, or otherwise not generally used in the normal course of business or email communication.
* `umbrella_top_1m.csv`: [Cisco Umbrella](https://umbrella.cisco.com/blog/cisco-umbrella-1-million) top domains based on passive DNS data. 
* `umbrella_top_1m_tld.csv`: [Cisco Umbrella](https://umbrella.cisco.com/blog/cisco-umbrella-1-million) top TLDs based on passive DNS data.
* `url_shorteners.txt`: Known URL shorteners that allow anyone to host arbitrary content.

Shoutout to @SwiftOnSecurity for [SwiftFilter](https://github.com/SwiftOnSecurity/SwiftFilter) which inspired many of the suspicious subjects and content.
