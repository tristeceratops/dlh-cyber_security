#!/usr/bin/env python3
import dns.resolver


def query_dns_records(domain_name):
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    result = {}
    for r_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, r_type)
            result[r_type] = answers
        except dns.resolver.NoAnswer as e:
            print(f"No answer for {domain_name} for record {r_type} -> : {e}")
        except dns.resolver.NXDOMAIN as e:
            print(f"NXDOMAIN for {domain_name} for record {r_type} -> : {e}")
        except dns.resolver.NoNameservers as e:
            print(f"No answer for {domain_name} for record {r_type} -> : {e}")
        except Exception as e:
            print(f"Error: {e}")
    return result


if __name__ == "__main__":
    import sys
    domain_name = sys.argv[1]
    results = query_dns_records(domain_name)
    for record_type, response_text in results.items():
        print(f"\n{record_type} Records:")
        print(response_text.response.to_text())
    print("\nResults dictionary:", results)
