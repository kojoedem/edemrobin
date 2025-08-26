import ipaddress

def allocate_subnet(block: str, cidr: str, used_subnets: list[str]):
    # cidr expected like "/30" or "192.168.1.8/30"
    if "/" not in cidr:
        raise ValueError("CIDR must include a slash, e.g. /30")
    try:
        # Accept "/30" or "x.x.x.x/30"; we only use prefix length
        if cidr.startswith("/"):
            new_prefix = int(cidr[1:])
        else:
            new_prefix = int(cidr.split("/")[1])
    except Exception as e:
        raise ValueError("Invalid CIDR format") from e

    network = ipaddress.ip_network(block, strict=True)
    for subnet in network.subnets(new_prefix=new_prefix):
        if str(subnet) not in used_subnets:
            return str(subnet)
    return None
