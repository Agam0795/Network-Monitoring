#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Vercel serverless wrapper for the Network Monitoring Dashboard
"""
from app import app, socketio

# Vercel uses WSGI, not Socket.IO's async server
# For Vercel, we'll serve the Flask app directly
application = app

# Handler for Vercel
def handler(request, context):
    return application
