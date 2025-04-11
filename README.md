# 🔐 SSH Hardening Home Lab – Enhancing SSH Security with Fail2Ban, UFW, KeyAuth and Tailscale.

## 📌 Lab Overview
This home lab demonstrates my ability to secure remote SSH access on a Kali Linux virtual machine using free, open-source tools. Following a **defense-in-depth** approach, it implements multiple security layers to mitigate potential threats and enhance system resilience, including:

✅ Hardened SSH server (port change, root login disabled, key-based authentication).<br>
✅ Fail2Ban to prevent brute-force attacks.<br>
✅ UFW (Uncomplicated Firewall) to restrict access.<br>
✅ Tailscale VPN for secure remote access with a Zero Trust approach.

This setup provides a **practical, production-ready** solution for secure remote server management.

---

ℹ️ **Disclaimer:**
All IP addresses in this lab have been masked for security and privacy purposes. Placeholders such as `<KALI_IP>` are used in place of specific IP addresses. Additionally, in any screenshots provided, IP addresses have been blocked or blurred to further protect sensitive information.

---

### 🌟 Table of Contents 🌟

1. **📦 [Step 1: Updating System & Checking Connectivity](#step-1-updating-system--checking-connectivity)**  
   - 📋 [Step 1 Summary](#-step-1-summary)

2. **🔧 [Step 2: Configuring My SSH Server](#step-2-configuring-my-ssh-server)**  
   - 📋 [Step 2 Summary](#-step-2-summary)

3. **🛡️ [Step 3: Securing My SSH with UFW (Uncomplicated Firewall)](#step-3-securing-my-ssh-with-ufw-uncomplicated-firewall)**  
   - 📋 [Step 3 Summary](#-step-3-summary)

4. **🔒 [Step 4: Protecting My SSH with Fail2Ban](#step-4-protecting-my-ssh-with-fail2ban)**  
   - 📋 [Step 4 Summary](#-step-4-summary)

5. **🔑 [Step 5: Switching to Key-Based Authentication](#step-5-switching-to-key-based-authentication)**  
   - 📋 [Step 5 Summary](#-step-5-summary)

6. **🌐 [Step 6: Securing Remote Access with Tailscale](#step-6-securing-remote-access-with-tailscale)**  
   - 📋 [Step 6 Summary](#-step-6-summary)

7. **🎉 [Lab Conclusion](#lab-conclusion)**  

8. **🔐 [Why This SSH Security Lab is Valuable for Businesses](#business-value)**  


<h1>Step 1: Updating System & Checking Connectivity</h1>

<p>I started my Kali Linux VM, logged in as kali, and opened a terminal. I updated the system:</p>

<pre><code class="language-bash">sudo apt update && sudo apt upgrade -y</code></pre>

<p>I verified network connectivity:</p>

<pre><code class="language-bash">ping -c 4 8.8.8.8</code></pre>

<img src="https://i.imgur.com/zQ0TlbG.png">

### ✍🏻 Step 1 Summary:

In Step 1, a Kali Linux VM was started, and the system was updated using `sudo apt update && sudo apt upgrade -y` to ensure it had the latest packages and security patches. Network connectivity was confirmed with a successful `ping -c 4 8.8.8.8`, verifying the VM was network-ready for an SSH security lab.

<h1>Step 2: Configuring My SSH Server</h1>

<h3>I installed the OpenSSH server & made sure that it was running:</h3>

<img src="https://i.imgur.com/YOnze2l.png">

<p>I installed the SSH server:</p>
<pre><code class="language-bash">sudo apt install openssh-server -y</code></pre>

<p>I started the SSH server:</p>
<pre><code class="language-bash">sudo systemctl start ssh</code></pre>

<p>I checked whether the SSH server was active or disabled:</p>
<pre><code class="language-bash">sudo systemctl status ssh</code></pre>

<hr>

<h3>I edited the SSH config to use port 5822:</h3>

<pre><code class="language-bash">sudo nano /etc/ssh/sshd_config</code></pre>

<img src="https://i.imgur.com/1mHw47S.png">
<img src="https://i.imgur.com/2BLzTlJ.png">

I changed **Port 22** to **Port 5822** and set <code>PermitRootLogin no</code> for security. I saved, exited, and restarted SSH:

✅ **Benefits of Changing the SSH Port**

• _**Reduces Automated Attacks**_ 🛑 <br>
        Most bots and automated scanners typically target port 22 by default. Changing it to a less common port helps minimise random brute-force attempts.<br>

• _**Less Noise in Logs**_ 📉 <br>
        Logs won’t be flooded with failed login attempts on port 22, making it easier to spot real threats.<br>
    
• _**Slows Down Attackers**_ 🕵️ <br>
        While not foolproof, attackers need to scan for the new port, which adds another step before they can attempt brute force attacks.<br>
    </li>
</ol>

<h3>I verified SSH listens on port 5822:</h3>

<img src="https://i.imgur.com/fMjQgcY.png">

<p>The screenshot above shows the <code>sudo netstat -tuln | grep 5822</code> output, confirming my SSH server on the Kali Linux VM listens on port 5822. This verifies the custom port configuration for my SSH’s security.</p>

<pre><code class="language-bash">sudo netstat -tuln | grep 5822</code></pre>

✅ **5822/tcp**, Action: ALLOW, From: Anywhere: This means UFW is also allowing TCP traffic on port 5822 for `IPv4` from any source. <br>

✅ **5822/tcp (v6)**, Action: ALLOW, From: Anywhere (v6) : This means UFW is allowing TCP traffic on port 5822 for `IPv6` from any source.

### ✍🏻 Step 2 Summary:

In Step 2, an SSH server was installed on the Kali Linux VM using `sudo apt install openssh-server -y`, started with `sudo systemctl start ssh`, and its status was checked. The SSH configuration was edited (`/etc/ssh/sshd_config`) to change the default port from 22 to 5822 and disable root login (`PermitRootLogin no`) for enhanced security, then restarted. The new port was verified with `sudo netstat -tuln | grep 5822`, confirming SSH was listening on 5822 for both IPv4 and IPv6, reducing automated attack risks.


<h1>Step 3: Securing My SSH with UFW (Uncomplicated Firewall)</h1>

<img src="https://i.imgur.com/REu1Jl7.png">

<p>This screenshot presents the <code>sudo ufw status</code> output, showing UFW configured to allow SSH traffic only on port 5822. This step restricts network access, enhancing my Kali Linux VM’s security for the SSH.</p>

### Steps I took to enable and configure the UFW: <br>

<p>I installed UFW:</p>
<pre><code class="language-bash">sudo apt install ufw -y</code></pre>

<p>I allowed SSH on port 5822:</p>
<pre><code class="language-bash">sudo ufw allow 5822/tcp</code></pre>

<p>I enabled UFW:</p>
<pre><code class="language-bash">sudo ufw enable</code></pre>

<p>I checked the status:</p>
<pre><code class="language-bash">sudo ufw status</code></pre>

<p>The output showed 5822/tcp allowed.</p>

### ✍🏻 Step 3 Summary:

In Step 3, the Uncomplicated Firewall (UFW) was installed on the Kali Linux VM using `sudo apt install ufw -y`. It was configured to allow SSH traffic only on port 5822 with `sudo ufw allow 5822/tcp`, then enabled with `sudo ufw enable`. The status was verified using `sudo ufw status`, confirming that only port 5822/tcp was open, enhancing SSH security by restricting network access.


<h1>Step 4: Protecting My SSH with Fail2Ban</h1>

<img src="https://i.imgur.com/V70PV9m.png">

<p>I installed Fail2Ban:</p>
<pre><code class="language-bash">sudo apt install fail2ban -y</code></pre>

<p>Fail2Ban is an intrusion prevention tool (IPS) for Linux that protects servers from brute-force attacks by monitoring log files and banning IPs that show signs of malicious activity.</p>

🔹 **Purpose & How It Works:**
<ul>
    <li>Watches logs for failed login attempts.</li>
    <li>If too many failures occur in a short time, it blocks the IP temporarily using firewall rules (UFW that we enabled previously).</li>
    <li>After the ban period, the IP is automatically unblocked.</li>
</ul>

🔥 **Why It's Useful:**
<ul>
    <li>✅ Protects SSH & other services from brute-force attacks.</li>
    <li>✅ Reduces server load by blocking repeated login attempts.</li>
    <li>✅ Automated banning improves security with minimal effort.</li>
</ul>

<h3>I modified Fail2Ban's `jail.local` file to customise the security rules:</h3>

<pre><code class="language-bash">sudo nano /etc/fail2ban/jail.local</code></pre>

<img src="https://i.imgur.com/jNUjOD4.png">

**Added the following rules:**

<p>[sshd]</p>
<pre><code class="language-bash">enabled = true
port = 5822
filter = sshd
logpath = /var/log/fail2ban.log
maxretry = 3
bantime = 3600
findtime = 600
banaction = iptables-multiport</code></pre>

<p>[sshd-persistent]</p>
<pre><code class="language-bash">enabled = true
port = 5822
filter = sshd
logpath = /var/log/fail2ban.log
maxretry = 5
bantime = 86400
findtime = 3600
banaction = iptables-multiport</code></pre>

🔹 **First Rule: [sshd]** <br>

This protects SSH on port 5822 with a temporary ban for failed logins. <br>

**enabled** = true → `This rule is active.` <br>
**port** = 5822 → `Monitors SSH running on port 5822 (not the default 22).` <br>
**filter** = sshd → `Uses the sshd filter (default for detecting SSH login failures).` <br>
**logpath** = /var/log/fail2ban.log → `Reads login attempts from the new fail2ban log file.` <br>
**maxretry** = 3 → `If an IP fails 3 login attempts within a certain time, it gets banned.` <br>
**bantime** = 3600 → `The ban lasts 1 hour (3600 seconds).` <br>
**findtime** = 600 → `If 3 failed attempts occur within 10 minutes (600 seconds), the IP is banned.` <br>
**banaction** = iptables-multiport → `Uses iptables to block the attacking IP on multiple ports.` <br>


📌 **Summary:** If someone enters the wrong SSH password 3 times within 10 minutes, they are banned for 1 hour. <br></p>

🔹 **Second Rule: [sshd-persistent]** <br>

This is a stricter rule for persistent attackers. <br></p>

**maxretry** = 5 → `Allows 5 failed login attempts before banning.` <br>
**bantime** = 86400 → `The ban lasts 24 hours (1 day).` <br>
**findtime** = 3600 → `If 5 failed attempts happen within 1 hour, the ban is triggered.` <br>


📌 **Summary:** If someone keeps failing 5 times within 1 hour, they are banned for an entire day. <br>

<h3>Created a dedicated log file for Fail2Ban:</h3>

<img src="https://i.imgur.com/DznABVL.png">

<p>Log files will be saved to <code>/var/log/fail2ban.log</code></p>

<p>Currently, the Fail2Ban logs are stored in the systemd journal, as the dedicated log file does not exist. To keep the Fail2Ban logs separate and organised, I will manually create the log file as outlined above.</p>

<p>To do this I will first create the Fail2Ban log file and edit its permissions:</p>

<img src="https://i.imgur.com/UUd5mBX.png">

<p>The following commands create a dedicated Fail2Ban log file, set its ownership to root:root, and adjust the file permissions to ensure it is readable and writable by the Fail2Ban service. This setup ensures proper logging for Fail2Ban while maintaining security.</p>

<ul>
    <li><code>sudo touch /var/log/fail2ban.log</code>: Creates the log file.</li>
    <li><code>sudo chown root:root /var/log/fail2ban.log</code>: Sets the file ownership to root.</li>
    <li><code>sudo chmod 640 /var/log/fail2ban.log</code>: Sets the correct file permissions, making it readable by root and the Fail2Ban service.</li>
</ul>

<p>And finally, I will restart Fail2Ban to apply the above changes: <code>sudo systemctl restart fail2ban</code></p>

<img src="https://i.imgur.com/2hKTYVu.png">

<p>After restarting, I enabled Fail2Ban and checked its status to ensure everything was running correctly, following the updates to the configuration files with the new rules and log path.</p>

<img src="https://i.imgur.com/bpMs7P7.png">

<p>This screenshot displays the <code>sudo fail2ban-client status sshd</code> output, confirming the Fail2Ban SSH jail is active and monitoring port 5822. This protects my SSH server against unauthorised access in my lab.</p>

<h3>Testing Fail2Ban:</h3>

<p>To test that Fail2Ban is working as expected, I attempted to SSH from my local Windows machine to the Kali VM, which is running both SSH and Fail2Ban. For this test, I set the ban duration to 2 minutes and configured Kali’s VM network setting to Bridged mode to ensure that Fail2Ban correctly detects the local Windows machine’s IP instead of using the Kali VM’s IP.</p>

<p>From my local Windows I ran the following command in PowerShell: <code>ssh kali@KALI_IP -p 5822</code></p>

<p>After typing the wrong password 3 times, I ran <code>sudo fail2ban-client status sshd</code> on the Kali VM to see if the ban has been registered.</p>

<img src="https://i.imgur.com/trFS77r.png">

<p>(Attempting to log in as the ‘kali’ user since 'root' SSH login was disabled earlier during SSH server configuration.)</p>

<p>Running the following command to inspect Fail2Ban logs:</p>
<pre><code class="language-bash">sudo cat /var/log/fail2ban.log | grep "Ban"</code></pre>

<img src="https://i.imgur.com/eZ4yKHP.png">

<p>This screenshot captures <code>/var/log/fail2ban.log</code>, showing an IP ban after multiple failed SSH attempts on port 5822. This proves my Fail2Ban configuration prevents brute-force attacks in my lab.</p>

### ✍🏻 Step 4 Summary:

In Step 4, Fail2Ban was installed (`sudo apt install fail2ban -y`) to safeguard the SSH server from brute-force attacks by monitoring logs and banning malicious IPs. The `jail.local` file was modified to set up two rules: one banning IPs after 3 failed SSH attempts on port 5822 for 1 hour, and another banning persistent attackers after 5 attempts for 24 hours. A dedicated log file (`/var/log/fail2ban.log`) was created with appropriate permissions, and Fail2Ban was restarted (`sudo systemctl restart fail2ban`) and enabled. The configuration was verified with `sudo fail2ban-client status sshd`, and a successful test from a Windows machine confirmed the ban after multiple failed SSH attempts, as recorded in the log.


<h1>Step 5: Switching to Key-Based Authentication</h1>

<img src="https://i.imgur.com/LFZ3uml.png">

<p>I generated an SSH key pair on my Windows 10 machine using Git Bash:</p>
<pre><code class="language-bash">ssh-keygen -t rsa -b 4096 -f /c/Users/newuser/.ssh/id_rsa</code></pre>

<p>(The <code>-b 4096</code> option specifies a 4096-bit key size, which is much stronger than the default 2048-bit.)</p>

<p>Listed files in the .ssh directory to confirm that the keys have been generated successfully:</p>
<pre><code class="language-bash">ls /c/Users/newuser/.ssh/</code></pre>

<p>I accepted the default location (<code>~/.ssh/id_rsa</code>) and left the passphrase empty. I copied the public key to my Kali VM using ssh-copy-id:</p>

<img src="https://i.imgur.com/vgZMQ0g.png">

<p>By using the <code>ssh-copy-id</code> command, I copied the public key to the <code>~/.ssh/authorized_keys</code> file on the Kali VM, enabling key-based authentication for secure, passwordless login.</p>

<img src="https://i.imgur.com/sCTY61j.png">

<p>The screenshot above verifies that the key has been copied successfully to my Kali VM.</p>

<img src="https://i.imgur.com/hw80bfR.png">
<img src="https://i.imgur.com/TwsILVX.png">

<p>Inside the SSH config file, I set <code>PasswordAuthentication no</code> and <code>PubkeyAuthentication yes</code>, saved, and restarted SSH. This disables password logins and enables key-based auth, enhancing my SSH’s security.</p>

<img src="https://i.imgur.com/0m5bR5p.png">

<p>I tested the connection from my local Windows using the <code>ssh -i ~/.ssh/id_rsa -p 5822 kali@KALI_IP</code> command. It successfully logged me into the Kali machine.</p>

### ✍🏻 Step 5 Summary:

In Step 5, an SSH key pair was generated on a Windows 10 machine using `ssh-keygen -t rsa -b 4096`, creating a 4096-bit key for stronger security. The public key was copied to the Kali VM with `ssh-copy-id`, enabling key-based authentication. The SSH configuration on the Kali VM was updated to disable password logins (`PasswordAuthentication no`) and enable key-based authentication (`PubkeyAuthentication yes`), followed by an SSH restart. The setup was tested successfully by logging into the Kali VM from Windows using the private key over port 5822.

# Step 6: Securing Remote Access with Tailscale

<h3>SSH Hardening Steps Implemented So Far:</h3>

<ul>
    <li><strong>Fail2Ban:</strong><br>
        Protects against brute-force attacks by banning IP addresses after multiple failed login attempts.
    </li>
    <li><strong>Changed Default SSH Port:</strong><br>
        Moves SSH from the default port (22) to a custom one, reducing exposure to automated attacks targeting the standard port.
    </li>
    <li><strong>Secured with UFW:</strong><br>
        Restricts SSH access to specific IP addresses and networks, enhancing control over incoming connections.
    </li>
    <li><strong>Key-Based Authentication:</strong><br>
        Replaces password authentication with SSH keys, significantly improving security by eliminating weaker password vulnerabilities.
    </li>
</ul>

<p>Each of these measures contributes to a multi-layered security strategy, known as <em>defence in depth</em>. If one layer is bypassed, the others remain intact, making the system much harder to compromise.</p>

<h3>Why Tailscale is the Final Step in This Defence-in-Depth Setup:</h3>
<p>Tailscale strengthens SSH security by setting up a private VPN network with WireGuard encryption. This removes the need for public-facing SSH ports, restricting access to devices within the Tailscale network. By encrypting all traffic and reducing the attack surface, it makes unauthorised access far more difficult. Plus, its fine-grained access controls ensure that only approved devices can connect, making remote access both simpler and more secure.</p>

<p>I installed Tailscale on my Kali VM, started the service, and authenticated it.</p>
<img src="https://i.imgur.com/ps1xA5q.png">

<p>I followed the browser link provided, signed up for a free Tailscale account, and authorised my Kali VM.<p>
<img src="https://i.imgur.com/lJNWFN5.png">

<p> Afterward, I checked the assigned Tailscale IP.</p>
<img src="https://i.imgur.com/hEzD79y.png">
<img src="https://i.imgur.com/hXT7VCk.png">

<p>On my Windows 10 machine, I downloaded and installed Tailscale from <a href="https://tailscale.com/download">tailscale.com/download</a>, signed in with the same account, and authorised the device.</p>
<img src="https://i.imgur.com/yYl3Huz.png">

<p>I tested the network connectivity between my Kali Linux machine and my local Windows system, "desktop-ed7nukg," using Tailscale. By running the ping command from Kali's terminal to the device's hostname, I successfully verified that the two devices could communicate over the secure Tailscale network, confirming the connection was working properly.</p>
<img src="https://i.imgur.com/6tMu7KD.png">

<p>Next, I connected to my Kali SSH server from my Windows 10 machine using the Kali VM’s Tailscale IP address (instead of its local IP from <code>ip a</code>). This demonstrated that SSH access works seamlessly within the Tailscale network.</p>

<p>To further test the setup, I created an Ubuntu VM as an additional client. I copied the SSH private key (<code>id_rsa</code>) generated earlier to this machine to enable SSH authentication. However, I intentionally did <em>not</em> add this Ubuntu VM to the Tailscale network. This test aimed to confirm that even with the correct SSH port and key, access would be denied without being connected to the Tailscale network.</p>
<img src="https://i.imgur.com/tPPB2zT.png">

<p>I transferred the private SSH key (<code>id_rsa</code>) to the Ubuntu machine using the <code>scp</code> command. The key was placed in the <code>~/.ssh/</code> directory of the <code>ubuntu</code> user, and the transfer completed successfully. This simulated a scenario where an attacker obtains a valid private key and attempts to authenticate. Despite knowing the SSH port and possessing the key, the attacker could not connect because the Ubuntu machine lacked a Tailscale network route to the Kali VM.</p>

<p>Finally, I tested the Tailscale configuration by attempting to SSH into the Kali VM from the Ubuntu machine (not on Tailscale) using the Kali VM’s Tailscale IP. The connection timed out, proving that only devices within the Tailscale network can access the Kali machine. This validates that Tailscale effectively blocks external connections, securing the system as intended.</p>
<img src="https://i.imgur.com/YJiKkiU.png">

### ✍🏻 Step 6 Summary:

In Step 6, Tailscale was implemented as a final layer of defense to secure SSH access by creating a private VPN network with WireGuard encryption, eliminating the need for public-facing SSH ports. Tailscale was installed and authenticated on the Kali VM, and a Tailscale IP was assigned. The same process was completed on a Windows 10 machine, enabling secure communication, confirmed by a successful ping test. SSH access was tested using the Kali VM’s Tailscale IP from Windows, proving seamless connectivity. An Ubuntu VM, excluded from Tailscale and equipped with the SSH private key, failed to connect to the Kali VM using its Tailscale IP, demonstrating that Tailscale effectively restricts access to only authorised devices within the network.

# Lab Conclusion

These actions collectively made my SSH server more secure by reducing its visibility to attackers, restricting access, and protecting against unauthorised entry, creating a robust, production-ready setup for secure remote access.

---
## 🔥 Security Features Implemented
- **📌 Fail2Ban**: Protects SSH from brute-force attacks.
- **🔐 Key-based Authentication**: Disables password logins for enhanced security.
- **🛡️ UFW Firewall**: Limits access to SSH on a non-default port.
- **🌐 Tailscale VPN**: Eliminates the need for public-facing SSH ports.
- **⚙️ Least Privilege Access**: Restricts SSH access to specific users.

## I displayed the following skills in my SSH security lab:

🔰 **Linux System Administration:** I effectively managed and configured a Kali Linux virtual machine, including updating the system, installing and managing services like OpenSSH, and troubleshooting network connectivity to ensure a stable environment for my lab. <br>

🔰 **Network Security:** I implemented secure remote access using Tailscale, a zero-trust networking solution, and configured UFW to restrict traffic to a custom SSH port (5822), demonstrating my ability to protect network infrastructure from unauthorised access and attacks. <br>

🔰 **Firewall Management:** I set up and configured UFW to allow only SSH traffic on a non-default port, showcasing my proficiency in using firewalls to minimise attack surfaces and enforce strict access controls. <br>

🔰 **Intrusion Prevention and Monitoring:** I installed and customised Fail2Ban to monitor SSH login attempts and block brute-force attacks, highlighting my skills in detecting and mitigating security threats in real-time. <br>

🔰 **Authentication Hardening:** I replaced password-based authentication with key-based authentication for SSH, disabling password logins to enhance security, demonstrating my expertise in implementing strong, cryptographic access controls. <br>

🔰 **Zero-Trust Networking:** I used Tailscale to establish secure, encrypted remote connections with continuous verification and least-privilege access, reflecting my understanding of modern zero-trust security principles. <br>

🔰 **Documentation and Problem-Solving:** I documented each step of my lab, including testing and verifying configurations, and resolved potential issues (e.g., ensuring network connectivity, testing Fail2Ban bans), showcasing my ability to troubleshoot and maintain secure systems. <br>

These skills collectively demonstrate my proficiency in cybersecurity, Linux administration, and network engineering, making this lab a strong showcase of my technical capabilities.

---

<a id="business-value"></a>
### 🔐 Why This SSH Security Lab is Valuable for Businesses

Businesses rely on secure remote access to manage critical systems, whether in the cloud or on-premises. This lab demonstrates **real-world security measures** that protect against cyber threats, ensuring business continuity and data integrity.  

### **Why Businesses Need This:**  

✅ **Prevents Costly Data Breaches** – Weak SSH security is a common entry point for hackers. This setup blocks brute-force attacks, disables password logins, and restricts access, reducing the risk of compromise.  

✅ **Reduces Downtime & IT Overhead** – Automated protections like Fail2Ban and UFW mean fewer security incidents, reducing the time and resources spent on monitoring and incident response.  

✅ **Supports Secure Remote Work** – Tailscale VPN allows employees and IT teams to securely access business servers **without exposing them to the internet**, making remote administration safe and seamless.  

✅ **Ensures Compliance with Security Standards** – Many industries (e.g., finance, healthcare, and legal sectors) require strict access controls. This setup aligns with **ISO 27001, NIST, and GDPR** best practices, helping businesses meet regulatory requirements.  

✅ **Protects Reputation & Customer Trust** – A security breach can damage a company’s reputation and lead to financial losses. By securing SSH access, businesses demonstrate a proactive approach to cybersecurity, strengthening customer and stakeholder confidence.  

### **Real-World Use Cases:**  

✔ **Secure IT Administration**

- Enables sysadmins and DevOps teams to manage systems remotely with minimal risk.  

✔ **Prevention of Ransomware & Cyber Attacks**

- Reduces attack vectors used by cybercriminals.

✔ **Protection of Business-Critical Systems**

- Ensures only authorised personnel can access sensitive infrastructure.  

This lab isn’t just theoretical—it provides **practical, business-ready security** that any organisation can implement to enhance its cybersecurity posture and **reduce risks in an increasingly hostile digital landscape**. 🔐🚀

