# Deployment Guide

This Network Monitoring Dashboard can be deployed to various platforms. Choose the option that best fits your needs.

## 🚀 Deployment Options

### ⚠️ Important: Real-time Limitations

This application uses **Socket.IO for real-time updates**, which requires:
- WebSocket support
- Long-running processes
- Background threads

**Vercel and similar serverless platforms** have limitations:
- ❌ No WebSocket support on free tier
- ❌ No background threads
- ❌ 10-second execution timeout
- ❌ No persistent connections

### ✅ Recommended Deployment Platforms

---

## 1. 🐳 Docker + Any VPS (Recommended)

**Best for:** Full features, real-time monitoring, complete control

### Create Dockerfile:

```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Expose port
EXPOSE 5000

# Run application
CMD ["python", "app.py"]
```

### Deploy:

```bash
# Build
docker build -t network-monitor .

# Run
docker run -d -p 5000:5000 \
  -e ADMIN_TOKEN=your-secure-token \
  -e SECRET_KEY=your-secret-key \
  --name network-monitor \
  network-monitor
```

---

## 2. 🚂 Railway.app (Easiest with Real-time)

**Best for:** Quick deployment, real-time features, free tier

### Steps:

1. **Go to:** https://railway.app
2. **Click:** "Start a New Project" → "Deploy from GitHub repo"
3. **Select:** Your Network-Monitoring repository
4. **Environment Variables:**
   ```
   ADMIN_TOKEN=your-secure-token
   SECRET_KEY=your-secret-key
   MONGO_URI=your-mongodb-uri (optional)
   ```
5. **Click:** Deploy

Railway will:
- ✅ Auto-detect Python
- ✅ Install requirements
- ✅ Support WebSockets
- ✅ Provide HTTPS domain
- ✅ Support background threads

**Cost:** Free tier includes 500 hours/month

---

## 3. 🌊 Render.com (Good Alternative)

**Best for:** Similar to Railway, good free tier

### Steps:

1. **Go to:** https://render.com
2. **New** → **Web Service**
3. **Connect:** GitHub repository
4. **Settings:**
   ```
   Name: network-monitoring
   Environment: Python 3
   Build Command: pip install -r requirements.txt
   Start Command: python app.py
   ```
5. **Environment Variables:**
   ```
   ADMIN_TOKEN=your-token
   SECRET_KEY=your-secret
   PORT=5000
   ```

**Cost:** Free tier available

---

## 4. ☁️ Heroku (Classic Option)

**Best for:** Enterprise-grade, easy scaling

### Create Procfile:

```
web: python app.py
```

### Deploy:

```bash
# Install Heroku CLI
# Then:
heroku login
heroku create network-monitoring-app
git push heroku main
heroku config:set ADMIN_TOKEN=your-token
heroku config:set SECRET_KEY=your-secret
heroku open
```

**Cost:** Starts at $7/month (no free tier anymore)

---

## 5. 🔵 DigitalOcean App Platform

**Best for:** Reliable hosting with good pricing

### Steps:

1. **Go to:** https://cloud.digitalocean.com/apps
2. **Create App** → **GitHub**
3. **Select:** Network-Monitoring repo
4. **Configure:**
   ```
   Run Command: python app.py
   HTTP Port: 5000
   ```
5. **Environment Variables:** Add your secrets

**Cost:** Starts at $5/month

---

## 6. 🖥️ VPS Deployment (Full Control)

**Best for:** Maximum control, custom configuration

### Any VPS (AWS EC2, DigitalOcean Droplet, Linode, etc.):

```bash
# SSH into your server
ssh user@your-server-ip

# Install Python
sudo apt update
sudo apt install python3 python3-pip git -y

# Clone repository
git clone https://github.com/Agam0795/Network-Monitoring.git
cd Network-Monitoring

# Install dependencies
pip3 install -r requirements.txt

# Set environment variables
export ADMIN_TOKEN=your-token
export SECRET_KEY=your-secret

# Run with screen or tmux
screen -S monitor
python3 app.py

# Detach: Ctrl+A, D
```

### With systemd (recommended):

Create `/etc/systemd/system/network-monitor.service`:

```ini
[Unit]
Description=Network Monitoring Dashboard
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/network-monitoring
Environment="ADMIN_TOKEN=your-token"
Environment="SECRET_KEY=your-secret"
ExecStart=/usr/bin/python3 /opt/network-monitoring/app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable network-monitor
sudo systemctl start network-monitor
sudo systemctl status network-monitor
```

---

## 7. 🌐 Nginx Reverse Proxy (Production)

For production VPS deployments:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## 📊 Platform Comparison

| Platform | Real-time | Background Jobs | Free Tier | Difficulty |
|----------|-----------|----------------|-----------|------------|
| Railway | ✅ Yes | ✅ Yes | ✅ 500h/mo | ⭐ Easy |
| Render | ✅ Yes | ✅ Yes | ✅ Limited | ⭐ Easy |
| Heroku | ✅ Yes | ✅ Yes | ❌ No | ⭐⭐ Medium |
| DigitalOcean | ✅ Yes | ✅ Yes | ❌ $5/mo | ⭐⭐ Medium |
| VPS | ✅ Yes | ✅ Yes | ❌ $5+/mo | ⭐⭐⭐ Hard |
| Vercel | ❌ Limited | ❌ No | ✅ Yes | ⭐ Easy |

---

## 🎯 Quick Recommendation

**For this project, I recommend:**

1. **Railway.app** (Best balance of ease + features + free tier)
2. **Render.com** (Good alternative to Railway)
3. **DigitalOcean VPS** (If you need more control)

**Avoid Vercel/Netlify/Cloudflare Pages** for this specific project because:
- They don't support WebSocket connections (real-time updates won't work)
- They don't support background threads (monitoring will fail)
- They have 10-second timeouts (long-running processes will die)

---

## 🚀 Quickest Deploy (Railway)

**5-minute deployment:**

1. Push to GitHub (already done)
2. Go to https://railway.app
3. Click "Start a New Project"
4. Select "Deploy from GitHub repo"
5. Choose "Network-Monitoring"
6. Add environment variables
7. Done! 🎉

Railway will give you a URL like: `https://network-monitoring-production.up.railway.app`

---

## 🔒 Security Tips

For production deployments:

```bash
# Generate secure secrets
python -c "import secrets; print(secrets.token_hex(32))"

# Set strong environment variables
ADMIN_TOKEN=<generated-token>
SECRET_KEY=<generated-secret>
ADMIN_PASS=<strong-password>
VIEWER_PASS=<strong-password>

# Optional: Configure MongoDB
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/
```

---

## 📝 Post-Deployment Checklist

- [ ] Test all endpoints
- [ ] Verify WebSocket connections work
- [ ] Check real-time updates are working
- [ ] Test login functionality
- [ ] Verify device management works
- [ ] Check reports generation
- [ ] Test chatbot responses
- [ ] Configure custom domain (optional)
- [ ] Set up SSL certificate (usually automatic)
- [ ] Configure environment variables
- [ ] Set up monitoring/logging

---

## 🆘 Need Help?

If you encounter issues:

1. **Check logs:** Most platforms provide log viewing
2. **Verify environment variables:** Make sure all secrets are set
3. **Test locally first:** Ensure `python app.py` works locally
4. **Check WebSocket support:** Confirm platform supports it
5. **Review port configuration:** Ensure the app binds to the correct port

---

**Choose Railway or Render for the fastest deployment with all features working!** 🚀
