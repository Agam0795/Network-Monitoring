# Deploy to Vercel (Limited Functionality)

## ⚠️ Important Limitations

Vercel deployment will have **limited functionality** because:

- ❌ **No WebSocket support** (real-time updates won't work)
- ❌ **No background threads** (monitoring loops disabled)
- ❌ **10-second timeout** (long-running tasks will fail)
- ❌ **No packet sniffing** (scapy features disabled)
- ✅ **Basic dashboard** (static views work)
- ✅ **Device management** (add/remove works)
- ✅ **Reports** (API endpoints work)

## 🚀 Deploy to Vercel Anyway

If you want to deploy to Vercel for demo purposes:

### Option 1: One-Click Deploy

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/Agam0795/Network-Monitoring)

### Option 2: Manual Deploy

```bash
# Install Vercel CLI
npm install -g vercel

# Login
vercel login

# Deploy
vercel
```

### Option 3: GitHub Integration

1. Go to https://vercel.com
2. Click "Add New Project"
3. Import your GitHub repository: `Agam0795/Network-Monitoring`
4. Click "Deploy"

### Environment Variables

Add these in Vercel dashboard:

```
ADMIN_TOKEN=your-secure-token
SECRET_KEY=your-secret-key
ADMIN_PASS=admin
VIEWER_PASS=viewer
```

## ✅ Better Alternative: Railway (Recommended)

For **FULL functionality** including real-time monitoring:

### Deploy to Railway (5 minutes):

1. **Go to:** https://railway.app
2. **Click:** "Start a New Project"
3. **Select:** "Deploy from GitHub repo"
4. **Choose:** `Agam0795/Network-Monitoring`
5. **Add environment variables:**
   ```
   ADMIN_TOKEN=your-token
   SECRET_KEY=your-secret
   ```
6. **Click:** Deploy

Railway gives you:
- ✅ WebSocket support (real-time updates work)
- ✅ Background threads (monitoring works)
- ✅ No timeout limits
- ✅ Free 500 hours/month
- ✅ Custom domain support
- ✅ HTTPS automatic

**Railway URL example:** `https://network-monitoring-production.up.railway.app`

## 📊 What Works Where

| Feature | Vercel | Railway | Render |
|---------|--------|---------|--------|
| Dashboard View | ✅ | ✅ | ✅ |
| Real-time Updates | ❌ | ✅ | ✅ |
| Device Monitoring | ❌ | ✅ | ✅ |
| Background Jobs | ❌ | ✅ | ✅ |
| Reports | ✅ | ✅ | ✅ |
| Chatbot | ✅ | ✅ | ✅ |
| Topology | ✅ | ✅ | ✅ |
| Free Tier | ✅ | ✅ 500h | ✅ Limited |

## 🎯 Final Recommendation

**Don't use Vercel for this project.** Use:

1. **Railway.app** ⭐⭐⭐⭐⭐
2. **Render.com** ⭐⭐⭐⭐
3. **DigitalOcean** ⭐⭐⭐⭐

See `DEPLOYMENT.md` for complete deployment guides.

---

**Need help?** Check the full deployment guide or open an issue on GitHub.
