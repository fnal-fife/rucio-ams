import sys
import os
import argparse
import uuid
import random
import subprocess
import logging
import threading
import stomp
import time
import queue

logging.basicConfig(format='%(asctime)-15s %(name)s %(levelname)s %(message)s', level=logging.INFO)
logging.getLogger('stomp.py').setLevel(logging.WARNING)
logger = logging.getLogger('transfer_test')

class Sentinel:
    pass

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--experiment',
        help='Name of the experiment this transfer test will be run for')
    parser.add_argument('--cert',
        help='PEM certificate for Rucio authentication')
    parser.add_argument('--key',
        help='PEM key for Rucio authentication')
    parser.add_argument('--host',
        help='Rucio message broker to connect to in order to listen to the event stream.')
    parser.add_argument('--port',
        type=int,
        help='Rucio message broker to connect to in order to listen to the event stream.')
    parser.add_argument('--topic',
        help='Message topic to connect to.')
    parser.add_argument('--durable',
        help='')
    parser.add_argument('--unsubscribe',
        help='')
    parser.add_argument('--start_rse',
        help='Rucio RSE to upload transfer files to.')
    parser.add_argument('--end_rses',
        help='Comma-separated list of RSEs that the generated transfer files will be have rules created for.')
    parser.add_argument('--rucio_account',
        default='root',
        help='User that Rucio commands will be run as')
    parser.add_argument('--num_files',
        default = 1,
        type=int,
        help='Number of files that will be generated the rules to transfer.')
    parser.add_argument('--file_size',
        default = 1024,
        type=int,
        help='Size of each generated test transfer file')
    parser.add_argument('--data_dir',
        default = '/tmp/%s' % str(uuid.uuid1()),
        help='Where to store the temporary data generated for this test.')
    parser.add_argument('--debug',
        help='Enable debug level logging.')
    return parser.parse_args()

class RucioTransferTest:
    def __init__(self, rucio_account, data_dir, file_size, start_rse):
        self.rucio_account = rucio_account
        self.data_dir = data_dir
        self.file_size = file_size
        self.start_rse = start_rse
        self.rules = queue.Queue()
        self.listener_thread = None
        self.is_subscribed = threading.Event()
        self.rules_to_monitor = []

    def create_file(self):
        filename = uuid.uuid1()
        abs_filepath = self.data_dir + '/' + str(filename)
        of = 'of={data_dir}/{filename}'.format(data_dir=self.data_dir, filename=filename)
        bs = 'bs={file_size}'.format(file_size=self.file_size)
        filegen_proc = subprocess.run(['dd', 'if=/dev/random',
            of,
            bs,
            'count=1'
        ])
        assert filegen_proc.returncode == 0
        return abs_filepath

    def rucio_upload(self, filepath):
        account_arg = '-a {rucio_account}'.format(rucio_account=self.rucio_account)
        rse_arg = '--rse {start_rse}'.format(start_rse=self.start_rse)
        cmd = 'rucio {account_arg} upload {rse_arg} {filepath}'.format(account_arg=account_arg, rse_arg=rse_arg, filepath=filepath)
        logger.info(f'Running command: {cmd}')
        rucio_upload_proc = subprocess.run(cmd, shell=True)
        assert rucio_upload_proc.returncode == 0

    def rucio_create_dataset(self, didfile_path, dataset_name=None):
        if not dataset_name:
            dataset_name = str(uuid.uuid1())
        account_arg = '-a {rucio_account}'.format(rucio_account=self.rucio_account)
        dataset_did = 'user.{rucio_account}:{dataset_name}'.format(rucio_account=self.rucio_account, dataset_name=dataset_name)
        cmd = 'rucio {account_arg} add-dataset {dataset_did}'.format(account_arg=account_arg, dataset_did=dataset_did)
        logger.info(f'Running command: {cmd}')
        rucio_create_ds_proc = subprocess.run(cmd, shell=True)
        assert rucio_create_ds_proc.returncode == 0
        return dataset_did

    def rucio_attach_dataset(self, dataset_did, didfile_path):
        account_arg = '-a {rucio_account}'.format(rucio_account=self.rucio_account)
        didfile_arg = '-f {didfile_path}'.format(didfile_path=didfile_path)
        cmd = 'rucio {account_arg} attach {dataset_did} {didfile_arg}'.format(account_arg=account_arg, dataset_did=dataset_did, didfile_arg=didfile_arg)
        logger.info(f'Running command: {cmd}')
        rucio_attach_ds_proc = subprocess.run(cmd, shell=True)
        assert rucio_attach_ds_proc.returncode == 0

    def rucio_add_rule(self, dataset_did, dest_rse, num_copies=1):
        account_arg = '-a {rucio_account}'.format(rucio_account=self.rucio_account)
        cmd = 'rucio {account_arg} add-rule {dataset_did} {num_copies} {dest_rse}'.format(
            account_arg=account_arg, dataset_did=dataset_did, num_copies=num_copies, dest_rse=dest_rse)
        logger.info(f'Running command: {cmd}')
        rucio_add_rule_proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        assert rucio_add_rule_proc.returncode == 0
        rule_id = rucio_add_rule_proc.stdout.strip().decode('utf-8')
        self.rules.put(rule_id)
        return rule_id

    def setup_listener(self, host, port, cert, key, topic, sub_id, vhost):
        logger.info('Creating the listener thread to monitor the Rucio event stream')
        sub_id = 'placeholder'
        self.listener_thread = threading.Thread(target=self.run_listener, args=(host, port, cert, key, topic, sub_id, vhost))
        self.listener_thread.start()
        return self.listener_thread

    def run_listener(self, host, port, cert, key, topic, sub_id, vhost):
        logger.info(f'Listener thread starting up. Connecting to {host}:{port}\n\tCert: {cert}\n\tKey: {key}\n\tTopic: {topic}\n\tSub ID: {sub_id}\n\tvhost: {vhost}')
        conn = stomp.Connection12(
            [(host, port)],
            use_ssl=True,
            ssl_cert_file=cert,
            ssl_key_file=key,
            vhost=vhost
            
        )
        rucio_listener = stomp.PrintingListener()
        conn.set_listener('RucioListener', rucio_listener)
        conn.connect(wait=True)
        conn.subscribe(topic, sub_id)
        logger.info(f'Listener thread successfully subscribed to topic: {topic}')
        self.is_subscribed.set()

        while True:
                
            logger.info(f'Listener waiting for rule.')
            new_rule = self.rules.get()
            self.rules_to_monitor.append(new_rule)
            logger.info(f'Listener thread got rule: {new_rule}')
            time.sleep(1)
        logger.info(f'Listener thread will monitor rules:\n\t{self.rules_to_monitor}')
            
            
        time.sleep(100000)    
        
        
        logger.info('Listener thread completing...')
        conn.disconnect()


def main(): 
    args = parse_args()

    tester = RucioTransferTest(
        args.rucio_account,
        args.data_dir,
        args.file_size,
        args.start_rse
    )
    # Start the listener thread
    vhost = '/'
    sub_id = 'test'
    listener_thread = tester.setup_listener(args.host, args.port, args.cert, args.key, args.topic, sub_id, vhost)
    while not tester.is_subscribed.is_set():
        time.sleep(1)
    logger.info(f'Rucio event stream Listener is ready.')

    # Generate the files that will be transferred
    logger.info(f'Generating {args.num_files}x{args.file_size}byte files')
    os.mkdir(args.data_dir)
    generated_files = []
    for i in range(args.num_files):
        filepath = tester.create_file()
        generated_files.append(filepath)
    logger.info(f'Generated {args.num_files} files')

    # Upload the test files to Rucio
    logger.info(f'Uploading {len(generated_files)} files')
    for f in generated_files:
        logger.info(f'Uploading: {f}')
        tester.rucio_upload(f)
    logger.info(f'Uploaded {len(generated_files)} files')

    # Create the DID file for specification of dataset files later
    logger.info('Creating the didfile')
    didfile_path = args.data_dir + '/' + 'didfile'
    with open(didfile_path, 'a') as df:
        for f in generated_files:
            did = 'user.{rucio_account}:{filename}\n'.format(rucio_account=args.rucio_account, filename=os.path.basename(f))
            df.write(did)
    logger.info('Created the didfile')

    # Create the Rucio dataset for these files
    dataset_did = tester.rucio_create_dataset(didfile_path)
    logger.info(f'Created Rucio dataset {dataset_did}')

    # Attach the generated files to the dataset via the didfile
    tester.rucio_attach_dataset(dataset_did, didfile_path)
    logger.info(f'Attached files in didfile to dataset {dataset_did}')

    # Create a rule for the dataset on each of the destination RSEs
    end_rses = args.end_rses.split(',')
    for dest_rse in end_rses:
        rule_id = tester.rucio_add_rule(dataset_did, dest_rse)
        tester.rules.put(rule_id)
        logger.info(f'Added rule {rule_id} to transfer dataset {dataset_did} from {args.start_rse} to {dest_rse}. Listener thread has been notified of rule.')
    tester.rules.put(Sentinel())
    

    # Now monitor for the completion of the transfers.
    logger.info(f'Commencing monitoring of transfer completion for {len(tester.rules_to_monitor)} rules:\n\t{tester.rules_to_monitor}')
    listener_thread.join()


if __name__ == '__main__':
    main()
