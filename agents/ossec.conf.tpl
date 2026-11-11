<!-- Rendered at container start by entrypoint.sh (envsubst). Do not edit inside the container. -->
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

  <!-- The one log source of this simulated host -->
  <localfile>
    <log_format>${LOG_FORMAT}</log_format>
    <location>/var/log/insurco/${LOG_FILE}</location>
  </localfile>

  <!-- Container-level modules are off: they describe the container, not the
       simulated host, and only add noise (rootcheck/CIS alerts seen in 2026). -->
  <rootcheck><disabled>yes</disabled></rootcheck>
  <sca><enabled>no</enabled></sca>
  <wodle name="syscollector"><disabled>yes</disabled></wodle>
  <syscheck><disabled>yes</disabled></syscheck>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
