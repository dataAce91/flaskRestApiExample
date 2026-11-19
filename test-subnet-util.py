
#!/usr/bin/env python3

import json
import csv
import glob
import os
import argparse
from collections import defaultdict
from datetime import datetime, timezone

IP_EVENTS = {
    "CreateNetworkInterface",
    "DeleteNetworkInterface",
    "AssignPrivateIpAddresses",
    "UnassignPrivateIpAddresses",
    "AttachNetworkInterface",
    "DetachNetworkInterface",
    "ModifyNetworkInterfaceAttribute",
}


def load_events(folder):
    records = []

    for filename in glob.glob(
        os.path.join(folder, "**", "*.json"), recursive=True
    ):
        try:
            with open(filename, encoding="utf-8") as f:
                data = json.load(f)

            events = data if isinstance(data, list) else data.get("Events", [])

            for item in events:
                raw = item.get("CloudTrailEvent", item)

                if isinstance(raw, str):
                    raw = json.loads(raw)

                if isinstance(raw, dict):
                    raw["_source_file"] = os.path.basename(filename)
                    records.append(raw)

        except Exception as exc:
            print(f"Error reading {filename}: {exc}")

    return records


def nested(obj, *keys):
    for key in keys:
        value = obj
        for part in key.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if value is not None:
            return value
    return None


def get_eni_id(event):
    request = event.get("requestParameters") or {}
    response = event.get("responseElements") or {}

    eni = (
        response.get("networkInterface")
        or response.get("networkInterfaceSet")
        or {}
    )

    eni_id = (
        request.get("networkInterfaceId")
        or eni.get("networkInterfaceId")
    )

    if not eni_id:
        for resource in event.get("resources", []):
            rid = resource.get("ResourceName", "")
            if rid.startswith("eni-"):
                return rid

    return eni_id


def get_subnet_id(event):
    request = event.get("requestParameters") or {}
    response = event.get("responseElements") or {}

    eni = (
        response.get("networkInterface")
        or response.get("networkInterfaceSet")
        or {}
    )

    return (
        request.get("subnetId")
        or eni.get("subnetId")
    )


def get_ips(obj):
    ips = set()

    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in (
                "privateIpAddress",
                "privateIp",
                "primaryPrivateIpAddress",
            ):
                if isinstance(value, str):
                    ips.add(value)

            elif isinstance(value, (dict, list)):
                ips.update(get_ips(value))

    elif isinstance(obj, list):
        for item in obj:
            ips.update(get_ips(item))

    return ips


def get_service(event, description=""):
    text = (
        str(description) + " "
        + str(event.get("eventSource", "")) + " "
        + str(event.get("userAgent", "")) + " "
        + str(event.get("invokedBy", ""))
    ).lower()

    if "elasticloadbalancing" in text or "elb " in text:
        return "Load Balancer"
    if "efs" in text or "elasticfilesystem" in text:
        return "EFS"
    if "lambda" in text:
        return "Lambda"
    if "nat gateway" in text or "nat_gateway" in text:
        return "NAT Gateway"
    if "vpcendpoint" in text or "vpc endpoint" in text:
        return "VPC Endpoint"
    if "ec2" in text:
        return "EC2"

    return "Other / Unknown"


def timestamp(event):
    value = event.get("eventTime", "")
    if not value:
        return ""

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).astimezone(timezone.utc).isoformat()
    except ValueError:
        return value


def analyze(records, target_subnet):
    records.sort(key=lambda e: timestamp(e) or "")

    eni_map = {}
    timeline = []
    subnet_totals = defaultdict(int)

    for event in records:
        name = event.get("eventName", "")

        if name not in IP_EVENTS:
            continue

        request = event.get("requestParameters") or {}
        response = event.get("responseElements") or {}

        eni_id = get_eni_id(event)

        if not eni_id:
            continue

        subnet = get_subnet_id(event)

        # Remember subnet ownership when it is present.
        if subnet:
            if eni_id not in eni_map:
                eni_map[eni_id] = {
                    "subnet": subnet,
                    "ips": set(),
                    "unknown": 0,
                    "description": "",
                    "service": "Other / Unknown",
                    "created": "",
                    "deleted": "",
                }
            else:
                eni_map[eni_id]["subnet"] = subnet

        state = eni_map.get(eni_id)

        # Recover subnet from previously observed ENI events.
        if not subnet and state:
            subnet = state["subnet"]

        if subnet != target_subnet:
            continue

        if state is None:
            state = {
                "subnet": target_subnet,
                "ips": set(),
                "unknown": 0,
                "description": "",
                "service": "Other / Unknown",
                "created": "",
                "deleted": "",
            }
            eni_map[eni_id] = state

        network_interface = (
            response.get("networkInterface")
            or response.get("networkInterfaceSet")
            or {}
        )

        description = (
            network_interface.get("description")
            or state["description"]
        )

        if description:
            state["description"] = description

        service = get_service(event, description)
        state["service"] = service

        before = len(state["ips"]) + state["unknown"]
        change = 0
        changed_ips = []
        detail = ""

        if name == "CreateNetworkInterface":
            state["created"] = timestamp(event)

            ips = get_ips(response) or get_ips(request)
            new_ips = ips - state["ips"]

            state["ips"].update(new_ips)
            changed_ips = sorted(new_ips)

            if not ips:
                # A newly created ENI normally has one primary IPv4.
                state["unknown"] += 1
                detail = "Primary IP inferred; exact address unavailable"
            else:
                detail = "ENI created"

        elif name == "AssignPrivateIpAddresses":
            ips = get_ips(request) or get_ips(response)
            new_ips = ips - state["ips"]

            state["ips"].update(new_ips)
            changed_ips = sorted(new_ips)

            count = request.get("secondaryPrivateIpAddressCount")

            if not ips and count:
                state["unknown"] += int(count)
                detail = f"{count} secondary IP(s) assigned; addresses unavailable"
            else:
                detail = "Private IP assignment"

        elif name == "UnassignPrivateIpAddresses":
            ips = get_ips(request) or get_ips(response)
            removed = ips & state["ips"]

            state["ips"].difference_update(removed)
            changed_ips = sorted(removed)
            detail = "Private IP release"

        elif name == "DeleteNetworkInterface":
            changed_ips = sorted(state["ips"])
            state["ips"].clear()
            state["unknown"] = 0
            state["deleted"] = timestamp(event)
            detail = "ENI deleted"

        elif name in (
            "AttachNetworkInterface",
            "DetachNetworkInterface",
        ):
            detail = "ENI attachment change; no IP delta inferred"

        elif name == "ModifyNetworkInterfaceAttribute":
            detail = "ENI attribute modification; no IP delta inferred"

        after = len(state["ips"]) + state["unknown"]
        change = after - before

        subnet_totals[target_subnet] += change

        identity = event.get("userIdentity") or {}

        username = (
            identity.get("userName")
            or identity.get("principalId")
            or identity.get("type", "")
        )

        timeline.append({
            "timestamp": timestamp(event),
            "region": event.get("awsRegion", ""),
            "subnet_id": target_subnet,
            "eni_id": eni_id,
            "service": state["service"],
            "event_name": name,
            "ip_change": change,
            "ips_before": before,
            "ips_after": after,
            "changed_ips": ";".join(changed_ips),
            "description": state["description"],
            "detail": detail,
            "username": username,
            "source_file": event.get("_source_file", ""),
        })

    eni_report = []

    for eni_id, state in eni_map.items():
        if state["subnet"] != target_subnet:
            continue

        eni_report.append({
            "eni_id": eni_id,
            "subnet_id": state["subnet"],
            "service": state["service"],
            "description": state["description"],
            "created": state["created"],
            "deleted": state["deleted"],
            "known_ip_count": len(state["ips"]),
            "unknown_ip_count": state["unknown"],
            "known_ips": ";".join(sorted(state["ips"])),
        })

    return timeline, eni_report, subnet_totals


def write_csv(filename, rows):
    if not rows:
        print(f"No data: {filename}")
        return

    with open(filename, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description="AWS subnet IP consumption investigation"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="CloudTrail JSON folder"
    )

    parser.add_argument(
        "--output",
        default="subnet-report",
        help="Output directory"
    )

    parser.add_argument(
        "--subnet-id",
        required=True,
        help="Target AWS subnet ID"
    )

    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    print("Loading CloudTrail JSON files...")
    records = load_events(args.input)

    print(f"Total events loaded: {len(records)}")
    print(f"Target subnet: {args.subnet_id}")

    timeline, enis, totals = analyze(
        records,
        args.subnet_id
    )

    write_csv(
        os.path.join(args.output, "event_timeline.csv"),
        timeline
    )

    write_csv(
        os.path.join(args.output, "eni_history.csv"),
        enis
    )

    summary = [{
        "subnet_id": args.subnet_id,
        "net_ip_change": totals[args.subnet_id],
        "event_count": len(timeline),
        "eni_count": len(enis),
    }]

    write_csv(
        os.path.join(args.output, "subnet_summary.csv"),
        summary
    )

    print("\nInvestigation completed")
    print("-----------------------")
    print("Subnet:", args.subnet_id)
    print("Events:", len(timeline))
    print("ENIs:", len(enis))
    print("Net reconstructed IP change:", totals[args.subnet_id])
    print("Reports:", args.output)


if __name__ == "__main__":
    main()
