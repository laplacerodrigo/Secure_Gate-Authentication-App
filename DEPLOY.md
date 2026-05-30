# SecureGate Deployment Guide

This guide deploys the Flask app on an Ubuntu VPS using:

- Nginx as the public web server
- Gunicorn as the Python app server
- systemd to keep the app running
- SQLite for the current local database
- Certbot for HTTPS

## 1. Prepare The Server

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip nginx git
```

## 2. Create App Directory

```bash
sudo mkdir -p /var/www/securegate
sudo chown -R $USER:$USER /var/www/securegate
cd /var/www/securegate
```

Copy your project files into this folder. If using GitHub:

```bash
git clone YOUR_REPO_URL .
```

## 3. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 4. Create Environment File

```bash
nano .env
```

Use:

```bash
LOGIN_WEB_SECRET_KEY=replace-with-a-long-random-secret
LAPLACE_DB_PATH=/var/lib/laplace/data/users.db
SESSION_COOKIE_SECURE=1
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_google_app_password
EMAIL_FROM=contact@laplace-electric.com
FLASK_DEBUG=0
```

Generate a strong secret:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

## 5. Test Gunicorn

```bash
source venv/bin/activate
set -a
source .env
set +a
gunicorn --bind 127.0.0.1:8000 wsgi:app
```

In another terminal:

```bash
curl http://127.0.0.1:8000
```

Stop Gunicorn with `Ctrl+C`.

## 6. Create systemd Service

```bash
sudo nano /etc/systemd/system/securegate.service
```

Paste:

```ini
[Unit]
Description=SecureGate Flask app
After=network.target

[Service]
User=YOUR_LINUX_USER
Group=www-data
WorkingDirectory=/var/www/securegate
EnvironmentFile=/var/www/securegate/.env
ExecStart=/var/www/securegate/venv/bin/gunicorn --workers 3 --bind unix:/var/www/securegate/securegate.sock wsgi:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Replace `YOUR_LINUX_USER`.

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl start securegate
sudo systemctl enable securegate
sudo systemctl status securegate
```

## 7. Configure Nginx

```bash
sudo nano /etc/nginx/sites-available/securegate
```

Paste:

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location ~* \.(db|log|env)$ {
        deny all;
        return 404;
    }

    location /static/ {
        alias /var/www/securegate/static/;
    }

    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/securegate/securegate.sock;
    }
}
```

Enable it:

```bash
sudo ln -s /etc/nginx/sites-available/securegate /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## 8. Point Domain DNS

In your domain provider, create:

```text
A record
Name: @
Value: YOUR_SERVER_IP

A record
Name: www
Value: YOUR_SERVER_IP
```

Wait for DNS propagation.

## 9. Add HTTPS

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

## 10. Useful Commands

Restart app:

```bash
sudo systemctl restart securegate
```

View app logs:

```bash
sudo journalctl -u securegate -f
```

View Nginx logs:

```bash
sudo tail -f /var/log/nginx/error.log
```
