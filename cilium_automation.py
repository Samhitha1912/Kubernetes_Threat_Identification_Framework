import json
import paramiko
import subprocess
import time

#Opening input JSON file
with open('C:\\Users\\Public\\input.json') as user_file:
  parsed_json = json.load(user_file)
clusters = parsed_json['clusterDetails']
print(clusters)
#For every cluster in the JSON file
for cluster in clusters:
  for i in range(len(cluster['masterIPs'])):
        print(cluster['masterIPs'][i])
        router_ip = cluster['masterIPs'][i]
        router_username = "rvce"
        router_password = "rvce@1963"

        ssh = paramiko.SSHClient()
        def ssh_connection_establishment(ip_address, username, password):
               # Load SSH host keys.
            ssh.load_system_host_keys()
            # Add SSH host key when missing.
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            total_attempts = 1
            for attempt in range(total_attempts):
                try:
                    print("Attempt to connect: %s" % attempt)
                    # Connect to router using username/password authentication.
                    ssh.connect(router_ip, 
                                username=router_username, 
                                password=router_password,
                                look_for_keys=True )
                except Exception as error_message:
                    print("Unable to connect")
                    print(error_message)
                    exit()

        
        def check_os_cmd(command):
            try:
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
                    # Read output from command.
                    output = ssh_stdout.readlines()
                    print(*output, sep = "\n")
                    return 

            except Exception as error_message:
                    print(error_message)
                    
        def helm_check():
              try:
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('helm version')
                output = ssh_stdout.readlines()
                if 'version.BuildInfo{Version' not in output:
                      helm_installation()
                return 
              
              except Exception as error_message:
                    print(error_message)
        
                    
        def helm_installation():
            try:
              ssh.exec_command('curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3')
              ssh.exec_command('sudo su')
              ssh.exec_command('chmod 700 get_helm.sh')
              ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('./get_helm.sh')
              output = ssh_stdout.readlines()
              print(*output, sep = "\n")
              
            except Exception as error_message:
                    print(error_message)
               
        def helm_version():
              try:
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('helm version')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                return 
              
              except Exception as error_message:
                    print(error_message)
                    
        def get_cilium_pods():
            cilium_pods=[]
            try:                
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('kubectl get pods -n kube-system | grep -v cilium-operator | grep cilium')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                for i in output:
                    cilium_pods.append(i.split(' ')[0])              
                return cilium_pods
            
            except Exception as error_message:
                    print(error_message)
                    
        def cilium_installation():
            try:       
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/v0.14.2/cilium-linux-amd64.tar.gz{,.sha256sum}')
                output =  ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('sha256sum --check cilium-linux-amd64.tar.gz.sha256sum')
                output =  ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin')
                output =  ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('rm cilium-linux-amd64.tar.gz{,.sha256sum}')
                output =  ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('cilium install --helm-set "prometheus.enabled=true" --helm-set "operator.prometheus.enabled=true"')
                output =  ssh_stdout.readlines()
                print(*output, sep = "\n")
            except Exception as error_message:
                    print(error_message)
                    
        def cilium_check():
            try:
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('kubectl get pods --all-namespaces')
                output = ssh_stdout.readlines()
                flag=0
                for entry in output:
                    if 'cilium' in entry:
                        flag=1
                        break
                       
                if flag==0:
                    print("=========================================================Begin Cilium Installation====================================================================================")
                    cilium_installation()
                    return 
                
            except Exception as error_message:
                    print(error_message)
                    
        def cilium_version():
            try:
                while True:
                    
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('kubectl get pods |  grep cilium')
                    output = ssh_stdout.readlines()
                    output_len=len(output)
                    i=0
                    for entry in output:
                        if 'Running' in entry:
                            print(entry)
                            i=i+1
                    if i==output_len:
                        break
                    else:
                        time.sleep(5)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('cilium version')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('cilium status')
                output = ssh_stdout.readlines()
                print(output)
                return 
                
            except Exception as error_message:
                    print(error_message)  
                    
        def prometheus_addon():
            try:       
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/HEAD/examples/kubernetes/addons/prometheus/monitoring-example.yaml')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")    
            except Exception as error_message:
                    print(error_message)  
        
        def prometheus_check():
            try:
                while True:
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('kubectl get pods -n cilium-monitoring |  grep prometheus')
                    output = ssh_stdout.readlines()
                    output_len=len(output)
                    i=0
                    for entry in output:
                        if 'Running' in entry:
                            print(entry)
                            i=i+1
                    if i==output_len:
                        break
                    else:
                        time.sleep(5)
                s='metrics1.json' 
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('kubectl -n cilium-monitoring port-forward service/prometheus 9090:9090 &')
                time.sleep(10)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("curl -s 'http://localhost:9090/api/v1/label/__name__/values'> metrics1.json")
                scp_cmd = ['scp', f'rvce@172.16.2.144:{s}', 'C:\\Users\\Public\\']
                subprocess.run(scp_cmd)
                output = ssh_stdout.readlines()
                with open('C:\\Users\\Public\\metrics1.json','r') as f:
                    metrics_json=json.load(f)
                    metrics_list=metrics_json['data']
                    f.close()
                #proc = subprocess.Popen(['ssh', 'rvce@172.16.2.140', 'bash', '-c', 'kubectl -n cilium-monitoring port-forward service/prometheus 9090:9090'])
                output_json=""
                with open('C:\\Users\\Public\\cilium_metrics_logs.json','a') as file2:
                    for metrics in metrics_list:
                        ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('curl http://localhost:9090/api/v1/query?query='+metrics)
                        output_json=''.join(ssh_stdout.readlines()).strip()
                        output_json=output_json+'\n'
                        file2.write(output_json)
                file2.close()
                return 
                
            except Exception as error_message:
                    print(error_message)  
            
        def report_generation(cilium_pods):
            i=1
            for cp in cilium_pods:
                try:    
                    s='cilium_node'+str(i)+'.txt'  
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('kubectl logs '+cp+ ' -n kube-system > '+s)
                    scp_cmd = ['scp', f'rvce@172.16.2.144:{s}', 'C:\\Users\\Public\\']
                    subprocess.run(scp_cmd)
                    output = ssh_stdout.readlines()
                except Exception as error_message:
                        print(error_message)
                i=i+1
    
        def ssh_closing():
              ssh.close()
              
        #ssh start
        ssh_connection_establishment(router_ip, router_username, router_password)
        #command to check os release
        check_os_cmd("cat /etc/os-release")
        #helm check & installation
        helm_check()
        #check helm version
        helm_version()
        #check for cilium, else installation
        cilium_check()
        #cilium version
        cilium_version()
        #prometheus installation
        prometheus_addon()
        #prometheus checking & port forwarding
        prometheus_check()        
        #get cilium pods
        ciliumpods= get_cilium_pods()
        #report generation: output in a cilium_node{i}.txt file (For each node in the cluster, a .txt file will be generated)
        report_generation(ciliumpods)
        #close ssh
        ssh_closing()