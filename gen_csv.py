from nanodurationpy import from_str

def geth_data() -> {}:
    geth_lines = []
    with open("geth_bench_output.log", "r") as f:
        geth_lines = f.read()

    geth_traces = geth_lines.split("0x")
    geth_traces = [[val for val in trace.split('\n') if val] for trace in geth_traces if trace][:-1]

    geth_traces = [(trace[0].split('/')[1], trace[2][17:]) for trace in geth_traces]

    result = {}
    for trace in geth_traces:
            result[trace[0]] = from_str(trace[1])

    return result

    
print("benchmark,geth-evm,evmone-baseline,evmone-advanced")
trace_result = geth_data()
import pdb; pdb.set_trace()
