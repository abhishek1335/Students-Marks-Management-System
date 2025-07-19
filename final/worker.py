# workers.py
import os
import redis
from rq import Worker, Queue, Connection
import sys

# Add the parent directory to the Python path so it can find 'config' and 'tasks'
# This is crucial if tasks.py and config.py are not in the same directory as workers.py
# If workers.py is at the root level alongside app.py, config.py, tasks.py, you might not need this.
# However, it's safer for Render deployments.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from tasks import process_pdf_task # Import your task function

# --- Redis Configuration ---
# Render Redis connection string is usually in REDIS_URL environment variable
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
conn = redis.from_url(redis_url)

if __name__ == '__main__':
    print("Starting RQ Worker...")
    with Connection(conn):
        # Listen on the default queue. You can specify multiple queues if needed:
        # worker = Worker(['high_priority', 'default', 'low_priority'], connection=conn)
        worker = Worker(Queue('default', connection=conn), default_result_ttl=5000) # Set default result TTL
        worker.work()
    print("RQ Worker stopped.")
