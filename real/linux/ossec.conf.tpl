<!-- real-linux-01. Rendered at container start by real-host-entrypoint.sh (envsubst). -->
<ossec_config>
  <client>
    <server>
      <address>${WAZUH_MANAGER}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>${WAZUH_MANAGER}</manager_address>
      <agent_name>${AGENT_NAME}</agent_name>
      <groups>${AGENT_GROUP}</groups>
    </enrollment>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
  </client>

  <!-- The REAL logs of this host, written by rsyslog (sshd, PAM) and auditd -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <!-- Same as the simulated hosts: container-level modules only add noise -->
  <rootcheck><disabled>yes</disabled></rootcheck>
  <sca><enabled>no</enabled></sca>
  <wodle name="syscollector"><disabled>yes</disabled></wodle>
  <syscheck><disabled>yes</disabled></syscheck>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
