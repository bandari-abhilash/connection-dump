for i in {7711..7788}; do
  echo "Sending to port $i..."
  for j in {1..10}; do
    echo "pkt$j" | nc -u 239.255.250.250 $i
    sleep 0.1
  done
done