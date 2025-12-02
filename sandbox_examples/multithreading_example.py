import multiprocessing as mp
import numpy as np
import os

def mixnet(input_array):
    output_array = []
    for elem in input_array:
        output_array.append(elem * 2)

    return np.asarray(output_array)

class AsyncOps():
    def __init__(self):
        self.output = []

    def mixnet_callback(self, AsyncResult):
        print('Callback: ')
        print(AsyncResult)
        # AsyncResult.get(timeout=1)

def test(jj):
    print(jj)

if __name__ == '__main__':
    ops = AsyncOps()

    # Start 4 worker processes
    num_procs = mp.cpu_count() - 1
    with mp.Pool(processes=num_procs) as pool:

        f_input = np.arange(10)

        # launching multiple evaluations asynchronously *may* use more processes
        sum_store = []
        multiple_results = [w_pool.apply_async(mixnet, args=(f_input, ), callback=test) for i in range(num_procs)]
        # multiple_results.wait()
        # print(multiple_results[0].get(timeout=1))
        # print([sum_store.append(res.get(timeout=1)) for res in multiple_results])

        try:
            print('End script...')
            # print(res.get(timeout=1))
        except mp.TimeoutError:
            print("We lacked patience and got a multiprocessing.TimeoutError")

        print("For the moment, the pool remains available for more work")
    # print(sum_store)

    running_sum = np.ones(10)
    for elem in sum_store:
        running_sum = running_sum * elem

    # print(running_sum)

    # exiting the 'with'-block has stopped the pool
    print("Now the pool is closed and no longer available")



























# Input to each proc (except main?)
#   Array to operate on
# Operations at each proc (on each element in input)
#   Depends on mixnet...

# import threading

# def send_tids(self):
#         t_start = time.time()

#         tid_bytes = self.pview.serialize_tids(self.pview.returned_tids)
#         thread_list = []
#         for dest_ip in self.party_ips:
#             keyproc_thread = threading.Thread(target=self.connect.send_msg, args=(dest_ip, tid_bytes))
#             keyproc_thread.start()
#             thread_list.append(keyproc_thread)

#         for t in thread_list:
#             t.join()

#         logging.info('Done returning tids.')
#         t_end = time.time()
#         return t_end - t_start



# self.n_pool = multiprocessing.cpu_count() - 1 or 1

