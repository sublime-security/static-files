## Overview

A collection of static files maintained by the Sublime team, primarily used for phishing defense.

## Repo contents

* `alexa_top_1m.csv`: [Alexa](https://www.alexa.com/topsites) top 1 million sites.
* `disposable_email_providers.txt`: Disposable (or temporary) email providers that generate short-lived email addresses not owned by or attributable to any single user.
* `file_extensions_common_archives.txt`: Common archive file extensions used to smuggle malicious files.
* `file_extensions_macros.txt`: File extensions of macro-supported documents, such as Microsoft Office files.
* `free_email_providers.txt`: Free email ("freemail") providers that allow anyone to create an email address. This is important to ensure the email address does not inherit the reputation of the freemail provider's domain. This list also includes the contents of the `disposable_email_providers.txt` list.
* `free_file_hosts.txt`: Sites that allow anyone to upload and serve arbitrary files or content. Content can include anything from a file preview with a clickable link to rendering HTML. This may include sites that uses arbitrary subdomains to load balance sites, but those subdomains are re-used for the site's users and are not unique to the owner of the content.
* `free_subdomain_hosts.txt`: Sites that allow anyone to create their own subdomain and host arbitrary content. This is important to ensure the subdomains do not inherit the reputation of the root domain. This includes both subdomains that are auto-generated as well as user-named subdomains. Subdomains are unique to the user that created it, and not re-used by the site for other users.
* `majestic_million.csv`: [Majestic million](https://majestic.com/reports/majestic-million) is a collection of domains that have the most referring subnets.
* `suspicious_content.txt`: Words or phrases that may be considered suspicious in an email body.
* `suspicious_subjects.txt`: Words or phrases that may be considered suspicious in an email subject.
* `suspicious_subjects_regex.txt`: Regular expressions for words or phrases that may be considered suspicious in an email subject.
* `suspicious_tlds.txt`: Top-level domains that are either frequently abused, free to register, or otherwise not generally used in the normal course of business or email communication.
* `tranco.csv`: [Tranco ranking](https://tranco-list.eu/), a research-oriented top sites ranking hardened against manipulation.
* `umbrella_top_1m.csv`: [Cisco Umbrella](https://umbrella.cisco.com/blog/cisco-umbrella-1-million) top domains based on passive DNS data. 
* `umbrella_top_1m_tld.csv`: [Cisco Umbrella](https://umbrella.cisco.com/blog/cisco-umbrella-1-million) top TLDs based on passive DNS data.
* `url_shorteners.txt`: Known URL shorteners that allow anyone to host arbitrary content.

Shoutout to @SwiftOnSecurity for [SwiftFilter](https://github.com/SwiftOnSecurity/SwiftFilter) which inspired many of the suspicious subjects and content.
