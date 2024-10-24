gunicorn -w 1 app:app -b 127.0.0.1:8001 &
sudo nginx -s quit
sudo nginx -c $PWD/nginx/nginx.conf -p $PWD/nginx/ -e $PWD/nginx/error.log &
sleep 2
read -p "Press Enter to shut down the server" </dev/tty
# pkill is used instead of kill because nginx spawns a new process
sudo pkill nginx
sudo pkill gunicorn