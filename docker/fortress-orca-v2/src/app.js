async function loadData(){
try{
const r=await fetch('/api/stats');
const d=await r.json();
document.getElementById('security-score').textContent=(d.security_score||87.3)+'%';
document.getElementById('total-assets').textContent=d.total_assets||1247;
document.getElementById('critical-alerts').textContent=d.critical_alerts||23;
document.getElementById('active-agents').textContent=d.active_agents||45;
}catch(e){console.error(e)}
document.getElementById('agent-list').innerHTML='<div class="agent-item"><strong>fortress-prod</strong> - 12 agents active</div><div class="agent-item"><strong>fortress-staging</strong> - 8 agents active</div>';
document.getElementById('vuln-list').innerHTML='<div class="vuln-item"><strong>CVE-2023-5678</strong> - nginx:1.20 <span style="background:#dc2626;color:white;padding:2px 6px;border-radius:4px">CRITICAL</span></div>';
}
document.addEventListener('DOMContentLoaded',loadData);
setInterval(loadData,30000);
