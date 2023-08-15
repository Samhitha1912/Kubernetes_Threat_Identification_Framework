import json
import paramiko
import subprocess
import time
import pprint
pp = pprint.PrettyPrinter(indent=4)

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
                    
        def get_falco_pods():
            falco_pods=[]
            try:                
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('kubectl get pods | grep -v falcosidekick | grep falco')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                for i in output:
                    falco_pods.append(i.split(' ')[0])
                #print(falco_pods)
                
                return falco_pods
            
            except Exception as error_message:
                    print(error_message)
                    
        def falco_installation():
            try:                
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('curl -L -O https://download.falco.org/packages/bin/x86_64/falco-0.34.1-x86_64.tar.gz')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('tar -xvf falco-0.34.1-x86_64.tar.gz')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('sudo cp -R falco-0.34.1-x86_64/* /')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('sudo apt update -y')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('sudo apt install -y dkms make linux-headers-$(uname -r)')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('sudo apt install -y clang llvm')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('sudo falco-driver-loader module')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('helm repo add falcosecurity https://falcosecurity.github.io/charts')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('helm repo update')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                ssh_stdin, ssh_stdout, ssh_stderr =ssh.exec_command('helm upgrade -i falco falcosecurity/falco \
  --set auditLog.enabled=true \
  --set falco.jsonOutput=true \
  --set falco.fileOutput.enabled=true')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
            except Exception as error_message:
                    print(error_message)
                    
        def falco_check():
            try:
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('kubectl get pods --all-namespaces')
                output = ssh_stdout.readlines()
                flag=0
                for entry in output:
                    if 'falco' in entry:
                        flag=1
                        break
                       
                if flag==0:
                    print("Begin Falco installation.")
                    falco_installation()
                    return 
                
            except Exception as error_message:
                    print(error_message)
                    
        def falco_version():
            try:
                while True:
                    
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('kubectl get pods | grep -v falcosidekick | grep falco')
                    output = ssh_stdout.readlines()
                    output_len=len(output)
                    i=0
                    for entry in output:
                        if 'Running' in entry:
                            pp.pprint(entry)
                            i=i+1
                    if i==output_len:
                        break
                    else:
                        time.sleep(5)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('falco --version')
                output = ssh_stdout.readlines()
                print(*output, sep = "\n")
                return 
                
            except Exception as error_message:
                    print(error_message)  
                                     
        def report_generation(falco_pods):
            i=1
            for fp in falco_pods:
                try: 
                   shell = ssh.invoke_shell()
                   shell.send('kubectl exec -it ' + fp + ' -- bash\n')
                   while not shell.recv_ready():
                        pass
                   while shell.recv_ready():
                        shell.recv(1024)
                   for j in range(10):
                        shell.send('cat /etc/shadow\n')
                        # Wait for the command to be executed and output to be available
                        while not shell.recv_ready():
                            pass
                        # Receive and print the output
                        output = shell.recv(1024).decode()
                        #print(output)
                    # Send the exit command
                   shell.send('exit\n')   
                   s='node'+str(i)+'.json'  
                   ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('kubectl logs -c falco '+fp + '| tail -n 1000 > '+s)
                   for i in range(len(cluster['masterIPs'])):
                    var=cluster['masterIPs'][i]
                    scp_cmd = ['scp', f'{var}:{s}', 'C:\\Users\\Public\\']
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
        #check for falco, else installation
        falco_check()
        #falco version
        falco_version()
        #get falco pods
        falcopods= get_falco_pods()
        #report generation: output in a node{i}.json file (For each node in the cluster, a JSON file will be generated)
        report_generation(falcopods)
        #close ssh
        ssh_closing()
       