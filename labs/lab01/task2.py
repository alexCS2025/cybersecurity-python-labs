import pyfiglet

users = {
    "blockchain_dev": {
        "role": "blockchain_developer",
        "clearance": 3,
        "department": "Blockchain",
        "active": True,
    },
    "smart_contract_auditor": {
        "role": "contract_auditor",
        "clearance": 3,
        "department": "Audit",
        "active": True,
    },
    "crypto_trader": {
        "role": "trader",
        "clearance": 2,
        "department": "Trading",
        "active": True,
    },
    "wallet_user": {
        "role": "wallet_user",
        "clearance": 1,
        "department": "Users",
        "active": True,
    },
    "mining_pool": {
        "role": "miner",
        "clearance": 1,
        "department": "Mining",
        "active": False,
    },
}
resources = [
    ("smart_contracts", 3),
    ("audit_reports", 3),
    ("trading_algorithms", 2),
    ("wallet_interface", 1),
    ("private_keys", 3),
    ("public_blockchain", 1),
    ("defi_protocols", 3),
    ("validator_nodes", 3),
    ("market_data", 2),
    ("community_forum", 1),
]
security_levels = (
    "Public Blockchain",
    "Permissioned",
    "Private Network",
    "Institutional",
)
blocked_users = {"mining_pool", "flash_loan_attack", "rug_pull_scam"}


def print_resources() -> None:
    """Print resources in a nice table"""
    print("=== Список ресурсів системи ===")
    print(f"{'Ресурс':<25} | {'Рівень безпеки'}")
    print("-" * 50)
    for res_name, level_num in resources:
        level_text = security_levels[level_num - 1]
        print(f"{res_name:<25} | {level_text}")
    print("\n")


def check_access(username: str, resource: tuple) -> tuple[str, str]:
    """Check if a user has an access to a particular resource"""
    try:
        _res_name, res_level = resource
    except TypeError as e:
        print("\nException!\n", e, sep="")
        return ("", "")

    if username not in users:
        return "DENY", "User not found"

    if username in blocked_users:
        return "DENY", "User is blocked"

    user_info = users[username]

    if not user_info.get("active", False):
        return "DENY", "Account inactive"

    user_clearance = user_info.get("clearance", 0)
    if user_clearance >= res_level:
        return "ALLOW", ""

    return "DENY", "Insufficient clearance"


def main():
    print_resources()
    for user in users:
        cool_username = pyfiglet.figlet_format(user, font="threepoint")
        print(f"\n{cool_username}\n")
        for resource in resources:
            res_name, _res_security_lvl = resource
            status, reason = check_access(user, resource)
            if status == "ALLOW":
                print(f"user=[{user}] resource=[{res_name}] -> ALLOW")
            else:
                print(f"user=[{user}] resource=[{res_name}] -> DENY ({reason})")


main()
