#!/bin/bash
# Checker execution
python3 /opt/scripts/health-checker.py

# Notifications sender
python3 /opt/scripts/slack_notifier.py
python3 /opt/scripts/email_notifier.py
