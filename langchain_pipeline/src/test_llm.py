from analyzer import analyze_logs

fake_log = """
2025-10-27T16:01:45Z ERROR nginx[2421]: Connection timeout from 10.0.0.45
2025-10-27T16:01:46Z WARN systemd[1]: Promtail service restart scheduled
"""

result = analyze_logs(fake_log)
print(result)