#!/bin/bash

OUTPUT_FILE="vulnerability_inventory.json"
FEED_FILE="cve_feed.json"

initialize_output() {
    echo '{"packages": []}' > "$OUTPUT_FILE"
}

get_installed_packages() {
    dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' 2>/dev/null
}

get_package_name() {
    echo "$1" | cut -d'/' -f1
}

get_candidate_version() {
    echo "$1" | awk '{print $2}'
}

get_installed_version() {
    echo "${INSTALLED_VERSIONS[$1]}"
}

get_source_pocket() {
    local package_name="$1"
    local source_pocket

    source_pocket=$(apt-cache policy "$package_name" 2>/dev/null | grep -E 'security|updates|backports' | grep -oP '\w+-\w+' | head -n 1)
    [ -z "$source_pocket" ] && source_pocket="unknown"

    echo "$source_pocket"
}

get_cves() {
    local package_name="$1"
    local cves

    cves=$(apt-get changelog "$package_name" 2>/dev/null | grep -o 'CVE-[0-9]\{4\}-[0-9]\+' | sort -u)

    if [ -z "$cves" ] && [ -d "/usr/share/ubuntu-advantage-tools" ]; then
        cves=$(grep -r "USN" /usr/share/ubuntu-advantage-tools 2>/dev/null | grep -i "$package_name" | grep -o 'CVE-[0-9]\{4\}-[0-9]\+' | sort -u)
    fi

    echo "$cves"
}

get_cve_array() {
    echo "$1" | jq -R -s -c 'split("\n")[:-1]'
}

get_severity() {
    local max_cvss="$1"

    awk -v m="$max_cvss" 'BEGIN {
        if (m == 0) print "unknown"
        else if (m < 4.0) print "low"
        else if (m < 7.0) print "medium"
        else if (m < 9.0) print "high"
        else print "critical"
    }'
}

write_package() {
    local package_name="$1"
    local installed_version="$2"
    local candidate_version="$3"
    local source_pocket="$4"
    local cve_array="$5"
    local max_cvss="$6"
    local severity="$7"
    local in_cisa_kev="$8"

    jq --arg pkg "$package_name" \
       --arg i_ver "$installed_version" \
       --arg c_ver "$candidate_version" \
       --arg pkt "$source_pocket" \
       --argjson cvs "$cve_array" \
       --argjson mx "$max_cvss" \
       --arg sev "$severity" \
       --argjson cisa "$in_cisa_kev" \
       '.packages += [{
           package: $pkg,
           installed_version: $i_ver,
           candidate_version: $c_ver,
           source_pocket: $pkt,
           cves: $cvs,
           max_cvss: $mx,
           severity: $sev,
           in_cisa_kev: $cisa
       }]' "$OUTPUT_FILE" > tmp.json && mv tmp.json "$OUTPUT_FILE"

    echo "Found and wrote: $package_name ($installed_version -> $candidate_version)"
}

initialize_output

declare -A INSTALLED_VERSIONS

while read -r package_name package_version; do
    package_name="${package_name%%:*}"
    INSTALLED_VERSIONS["$package_name"]="$package_version"
done < <(get_installed_packages)

declare -A CVSS_SCORES
declare -A CISA_KEV

if [ -f "$FEED_FILE" ]; then
    while IFS=$'\t' read -r cve_id cvss_score cisa_kev; do
        CVSS_SCORES["$cve_id"]="$cvss_score"
        CISA_KEV["$cve_id"]="$cisa_kev"
    done < <(jq -r 'to_entries[] | [.key, (.value.cvss // 0), (.value.in_cisa_kev // false)] | @tsv' "$FEED_FILE")
fi

apt list --upgradable 2>/dev/null | tail -n +2 | while read -r package_line; do
    package_name=$(get_package_name "$package_line")
    candidate_version=$(get_candidate_version "$package_line")
    installed_version=$(get_installed_version "$package_name")

    [ -z "$installed_version" ] && continue

    source_pocket=$(get_source_pocket "$package_name")
    cves=$(get_cves "$package_name")

    [ -z "$cves" ] && continue

    max_cvss=0.0
    in_cisa_kev="false"

    cve_array=$(get_cve_array "$cves")

    for cve_id in $cves; do
        cvss_score="${CVSS_SCORES[$cve_id]:-0}"
        cisa_kev="${CISA_KEV[$cve_id]:-false}"

        awk_result=$(awk -v c="$cvss_score" -v m="$max_cvss" 'BEGIN { if(c>m) print c; else print m }')
        max_cvss="$awk_result"

        [ "$cisa_kev" = "true" ] && in_cisa_kev="true"
    done

    severity=$(get_severity "$max_cvss")

    write_package \
        "$package_name" \
        "$installed_version" \
        "$candidate_version" \
        "$source_pocket" \
        "$cve_array" \
        "$max_cvss" \
        "$severity" \
        "$in_cisa_kev"
done

