from copy import deepcopy


def event(number=1, **changes):
    record = {
        "eventID": f"00000000-0000-4000-8000-{number:012d}",
        "eventTime": "2026-01-01T00:00:00Z",
        "eventSource": "iam.amazonaws.com", "eventName": "ListUsers", "awsRegion": "us-east-1",
        "recipientAccountId": "111122223333",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/synthetic", "accountId": "111122223333"},
        "sourceIPAddress": "192.0.2.10",
    }
    record.update(deepcopy(changes))
    return record
