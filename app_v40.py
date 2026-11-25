"""FilelessGuard AI: beginner-first local research dashboard."""
import json
from pathlib import Path
from datetime import datetime
import streamlit as st

st.set_page_config(page_title='FilelessGuard AI', page_icon='🛡️', layout='wide')
# Native theme is supplied in .streamlit/config.toml; CSS only adds accents.
st.markdown('''<style>
.stApp {background:#000;color:#fff} [data-testid="stSidebar"] {background:#080808}
[data-testid="stMetric"] {background:#101010;border:1px solid #333;border-radius:12px;padding:15px}
h1,h2,h3 {color:#67e8f9!important}
.stButton button, .stDownloadButton button {background:#151515!important;color:white!important;border:1px solid #777!important}
.stButton button *, .stDownloadButton button * {color:white!important}
.stButton button:hover, .stDownloadButton button:hover {background:#252525!important;border-color:#22d3ee!important}
.stButton button:focus-visible, .stDownloadButton button:focus-visible {outline:2px solid #22d3ee!important}
</style>''', unsafe_allow_html=True)
PAGES=['Home','Check my computer','Understand alerts','Process explorer','Security graphs','Try a safe demo','Learn about malware','About this project','Guard Assistant','Reports & privacy']
S=st.session_state
if 'page' not in S: S.page='Home'
def go(page): S.page=page
with st.sidebar:
    st.title('🛡️ FilelessGuard AI')
    st.caption('Local security research • v4.0 — all-in-one')
    st.radio('Where would you like to go?',PAGES,key='page')
    advanced=st.toggle('Advanced mode',False)
    st.caption('Advanced mode reveals technical details. It does not change your scan results.')
    save_history=st.toggle('Save scan totals locally',False)
    desktop_alerts=st.toggle('Windows alert pop-up',False)
    st.caption('Read-only prototype. Not an antivirus.')
page=S.page
labels={'BENIGN':'Low risk','SUSPICIOUS':'Needs review','MALICIOUS':'High risk'}

def scan(demo=False):
    import pandas as pd
    from src.detector import Detector
    from guard_v4 import hybrid, save_event, notify
    if not Path('models/rf_model.joblib').exists():
        st.error('Model missing. Run python train.py in VS Code.'); return
    try:
        with st.spinner('Analyzing records. Please wait...'):
            if 'engine' not in S: S.engine=Detector()
            if demo:
                from src.samples import SIMULATED_EVENTS
                records=list(SIMULATED_EVENTS)
            else:
                from src.collector import snapshot
                records=snapshot()
            result=hybrid(S.engine.score(records),records)
            if result.empty:
                st.warning('No records were available. Try again.'); return
            if demo: S.demo=result
            else:
                S.result=result
                S.parents={r["pid"]:r.get("ppid") for r in records}
                S.scan_time=datetime.now().strftime('%H:%M:%S')
                if save_history: save_event(result)
                if desktop_alerts and not S.get('auto_running',False) and (result.verdict=='MALICIOUS').any(): notify(int((result.verdict=='MALICIOUS').sum()))
                history=S.get('timeline',[])
                history.append({'Time':datetime.now(),'Needs review':int((result.verdict=='SUSPICIOUS').sum()),'High risk':int((result.verdict=='MALICIOUS').sum())})
                S.timeline=history[-120:]
    except Exception as exc:
        st.error('Scan could not finish. See technical details below.')
        with st.expander('Technical details'): st.exception(exc)

def summary(df):
    cols=st.columns(4)
    cols[0].metric('Checked',len(df))
    for c,(k,v) in zip(cols[1:],labels.items()): c.metric(v,int((df.verdict==k).sum()))
    st.caption('These are model classifications, not confirmed infections or guarantees of safety.')

def table(df):
    view=df.copy(); view['Result']=view.verdict.map(labels)
    view['Model score']=view.probability.map(lambda p:f'{p:.0%}')
    cols=['name','Result','Model score']
    if advanced: cols+=['pid','parent_name','indicator','cpu_percent','memory_mb']
    st.dataframe(view[cols].rename(columns={'name':'Application','pid':'Process ID','parent_name':'Parent application','indicator':'Detection indicator','cpu_percent':'CPU %','memory_mb':'Memory (MB)'}),hide_index=True,width='stretch')

def explain(row):
    st.subheader(str(row['name']))
    st.write('Result: **'+labels[row.verdict]+'**')
    st.write('The model and behavioral rules provide a review priority. Legitimate applications can also trigger alerts.')
    st.write('Why it was flagged: '+str(row.indicator))
    st.info('What to do: If you are concerned, check the application using Windows Security. Do not delete or stop it based only on this result.')
    if advanced:
        st.write('Process ID:',row.pid,' | Parent:',row.parent_name)
        st.metric('Model score (not calibrated infection probability)',f'{row.probability:.1%}')
        with st.expander('Command line — may contain private information'): st.code(str(row.cmdline))

def need_scan():
    st.info('You have not scanned your computer in this session yet.')
    st.button('Go to computer scan',on_click=go,args=('Check my computer',),key='go_scan')

if page=='Home':
    st.title('Your computer, made easier to understand')
    st.write('Check running applications for unusual activity. No cybersecurity experience required.')
    st.caption('Local research prototype • Read-only process inspection • Not an antivirus')
    if st.button('Start security scan',type='primary',width='stretch'):
        scan()
    if 'result' in S:
        import pandas as pd
        import altair as alt
        df=S.result
        st.subheader('Your latest scan')
        st.caption('Last scan: '+S.scan_time+' | Live records only')
        summary(df)
        counts=pd.DataFrame({'Result':list(labels.values()),'Count':[int((df.verdict==k).sum()) for k in labels]})
        left,right=st.columns(2)
        with left:
            st.altair_chart(alt.Chart(counts).mark_arc(innerRadius=65).encode(theta='Count:Q',color=alt.Color('Result:N',scale=alt.Scale(domain=list(labels.values()),range=['#22c55e','#f59e0b','#ef4444'])),tooltip=['Result','Count']).properties(height=260),width='stretch')
        with right:
            st.subheader('What should I do?')
            if (df.verdict!='BENIGN').any():
                st.write('Some applications need review. This does not prove infection. Do not stop or delete them based on this score.')
            else:
                st.write('No records were flagged. This does not guarantee that your computer is safe.')
            st.button('Understand my results',on_click=go,args=('Understand alerts',))
    else:
        st.info('Ready for your first scan. Results will appear here after you press Start security scan.')
    st.divider()
    st.subheader('System performance')
    st.caption('CPU and memory usage are performance measurements, not malware indicators.')
    if st.toggle('Show live CPU and memory',value=False):
        import psutil
        import pandas as pd
        @st.fragment(run_every=2)
        def performance():
            cpu=psutil.cpu_percent(interval=None)
            ram=psutil.virtual_memory().percent
            history=S.get('performance_history',[])
            history.append({'Time':datetime.now(),'CPU %':cpu,'Memory %':ram})
            S.performance_history=history[-60:]
            a,b=st.columns(2)
            a.metric('CPU usage',f'{cpu:.1f}%'); b.metric('Memory usage',f'{ram:.1f}%')
            st.line_chart(pd.DataFrame(S.performance_history).set_index('Time'))
        performance()
    st.divider()
    st.button('Ask Guard Assistant',on_click=go,args=('Guard Assistant',),width='stretch')
    st.subheader('Explore FilelessGuard')
    st.button('Explore application connections',on_click=go,args=('Process explorer',),width='stretch')
    a,b=st.columns(2)
    with a:
        st.subheader('Understand alerts'); st.write('Learn what unusual activity means and what to do next.'); st.button('View alerts',on_click=go,args=('Understand alerts',))
        st.subheader('Learn cybersecurity'); st.write('Explore malware, its effects and prevention.'); st.button('Start learning',on_click=go,args=('Learn about malware',))
    with b:
        st.subheader('Security graphs'); st.write('See your scan results visually.'); st.button('View graphs',on_click=go,args=('Security graphs',))
        st.subheader('Safe demonstration'); st.write('Try example threat records without executing malware.'); st.button('Try demo',on_click=go,args=('Try a safe demo',))
elif page=='Check my computer':
    st.title('Check my computer'); st.write('Press the button to inspect running applications. No scan starts automatically.')
    if st.button('Start security scan',type='primary',width='stretch'): scan()
    if 'result' in S:
        df=S.result; st.caption('Last scan: '+S.scan_time); summary(df)
        st.button('Explain my alerts',on_click=go,args=('Understand alerts',))
        with st.expander('View all applications',expanded=advanced):
            query=st.text_input('Search application name'); table(df[df.name.astype(str).str.contains(query,case=False,regex=False)])
        st.download_button('Save scan report (CSV)',df.drop(columns=['cmdline'],errors='ignore').to_csv(index=False),'scan_report.csv','text/csv')
    if advanced:
        interval=st.slider('Automatic scan interval (seconds)',5,60,15)
        auto=st.toggle('Repeat scans while this page is open',False)
        if auto:
            @st.fragment(run_every=interval)
            def repeat():
                S.auto_running=True
                try: scan()
                finally: S.auto_running=False
                if 'result' in S: summary(S.result); st.caption('Updated '+S.scan_time)
            repeat()
elif page=='Understand alerts':
    st.title('Understand your alerts'); st.write('Needs review means unusual activity. High risk means a higher model score, not confirmed malware.')
    if 'result' not in S: need_scan()
    else:
        df=S.result; flagged=df[df.verdict!='BENIGN']; summary(df)
        if flagged.empty: st.success('No records were flagged in this scan. This does not guarantee safety.')
        else:
            st.write('Choose an application to see why it was flagged.')
            idx=st.selectbox('Application',range(len(flagged)),format_func=lambda i:f"{flagged.iloc[i]['name']} — {labels[flagged.iloc[i].verdict]} (ID {flagged.iloc[i].pid})")
            explain(flagged.iloc[idx]); table(flagged)
        if advanced and 'logger' in S:
            with st.expander('Saved alert history (older versions may include demo records)'): st.dataframe(S.logger.history(100).drop(columns=['cmdline'],errors='ignore'),width='stretch')
elif page=='Process explorer':
    import json as _json
    st.title('Explore application connections')
    st.write('Choose a running process to see what launched it and what it launched. A connection alone is not evidence of malware.')
    if st.button('Refresh computer scan',type='primary'): scan()
    if 'result' not in S or 'parents' not in S:
        st.info('Start a scan to collect application connections.')
    else:
        df=S.result
        st.caption('Snapshot taken at '+S.scan_time+' • Live records only; not a continuously updated map.')
        query=st.text_input('Find an application',placeholder='Example: Chrome or Python')
        matches=df[df.name.astype(str).str.contains(query,case=False,regex=False)]
        if st.checkbox('Only show processes needing attention'):
            matches=matches[matches.verdict!='BENIGN']
        if matches.empty:
            st.info('No matching applications. Try another name or refresh the scan.')
        else:
            rows={int(r.pid):r for _,r in df.iterrows()}
            parents=S.parents
            chosen=st.selectbox('Choose an application',list(matches.pid.astype(int)),format_func=lambda pid:f'{rows[pid]["name"]} — {labels[rows[pid].verdict]} (ID {pid})')
            row=rows[chosen]
            colors={'BENIGN':'#22c55e','SUSPICIOUS':'#f59e0b','MALICIOUS':'#ef4444'}
            parent=parents.get(chosen)
            children=[pid for pid in rows if parents.get(pid)==chosen and pid!=chosen]
            shown=children[:20]
            def node(pid):
                r=rows[pid]
                label=_json.dumps(f'{r["name"]}\n{labels[r.verdict]} | ID {pid}',ensure_ascii=True)
                return f'n{pid} [label={label}, color="{colors[r.verdict]}"];'
            lines=['digraph {','graph [bgcolor="#000000", rankdir=TB];','node [shape=box, style="rounded,filled", fillcolor="#151515", fontcolor="#ffffff", fontname="Arial"];','edge [color="#aaaaaa"];',node(chosen)]
            if parent in rows and parent!=chosen:
                lines.extend([node(parent),f'n{parent} -> n{chosen};'])
            else:
                lines.extend(['unknown [label="Parent not available", color="#777777"];',f'unknown -> n{chosen} [style=dashed];'])
            for child in shown:
                if child==parent: continue
                lines.extend([node(child),f'n{chosen} -> n{child};'])
            lines.append('}')
            st.graphviz_chart('\n'.join(lines))
            st.caption(f'{len(children)} captured child processes; showing up to 20. Arrows point from parent to child. Missing parents may have exited or been inaccessible.')
            st.markdown('🟢 Low risk · 🟠 Needs review · 🔴 High risk')
            if row.verdict=='BENIGN':
                st.success('This process received a low model score. This does not guarantee safety.')
            else:
                explain(row)
            if st.button('Check executable publisher'):
                from guard_v4 import publisher
                try: st.code(publisher(chosen))
                except Exception as e: st.warning(f'Publisher unavailable: {e}')
            st.caption('Signature status is not proof of safety. A PID can change after a scan.')
            with st.expander('View connected applications'):
                ids=list(dict.fromkeys([chosen]+([parent] if parent in rows else [])+children))
                table(df[df.pid.isin(ids)])
elif page=='Security graphs':
    import pandas as pd
    import altair as alt
    st.title('Security graphs')
    if 'result' not in S: need_scan()
    else:
        df=S.result; summary(df)
        counts=pd.DataFrame({'Result':list(labels.values()),'Count':[int((df.verdict==k).sum()) for k in labels]})
        st.subheader('Application risk distribution')
        st.altair_chart(alt.Chart(counts).mark_arc(innerRadius=65).encode(theta='Count:Q',color=alt.Color('Result:N',scale=alt.Scale(domain=list(labels.values()),range=['#22c55e','#f59e0b','#ef4444'])),tooltip=['Result','Count']).properties(height=300),width='stretch')
        st.subheader('Alerts over time'); st.line_chart(pd.DataFrame(S.timeline).set_index('Time')); st.caption('Each point represents a scan in this session.')
        if advanced:
            for field in ['cpu_percent','memory_mb']:
                top=df.nlargest(10,field).copy(); top['Application']=top.name.astype(str)+' ('+top.pid.astype(str)+')'; st.subheader(field); st.bar_chart(top.set_index('Application')[field])
elif page=='Try a safe demo':
    st.title('Safe demonstration'); st.info('These are fictional text records. No malware is executed and demo alerts are not saved to the real alert log.')
    if st.button('Run demonstration',type='primary'): scan(True)
    if 'demo' in S:
        summary(S.demo); table(S.demo)
        for _,r in S.demo.iterrows():
            with st.expander(str(r['name'])+' — '+labels[r.verdict]): st.write(str(r.indicator))
elif page=='Learn about malware':
    st.title('Learn about fileless malware'); st.write('Fileless techniques can abuse legitimate tools and run code in memory, making some traditional file-based checks less effective.')
    for title,body in [('What is a process?','A running instance of an application or system service.'),('What is suspicious behavior?','An unusual pattern that deserves investigation, but is not proof of an attack.'),('What are the effects?','Possible data theft, credential compromise, resource misuse and business disruption.'),('How can I stay protected?','Keep Windows updated, use Windows Security, avoid untrusted attachments and use strong authentication.')]:
        with st.expander(title,expanded=True): st.write(body)
    st.caption('These are potential effects, not observed incidents on your computer.')
elif page=='Guard Assistant':
    st.title('Guard Assistant')
    st.caption('Local rule-based guide, not a generative AI or antivirus.')
    answers={'What does high risk mean?':'The model score and multiple behavioral indicators agree. This is a review priority, not proof of infection.','Why is Chrome flagged?':'Ordinary applications can resemble synthetic training patterns. Review the indicators and verify independently.','Should I delete a process?':'No. Do not terminate or delete a process based only on this tool. Use Windows Security for independent checks.','What is fileless malware?':'Malicious activity that can use legitimate tools and memory rather than relying on a conventional malicious executable.','What should I do next?':'Keep Windows updated, run Windows Security if concerned, and ask a trusted administrator for help.'}
    q=st.selectbox('Choose a question',list(answers)); st.info(answers[q])
    if 'result' in S:
        df=S.result; flagged=df[df.verdict!='BENIGN']
        if not flagged.empty:
            i=st.selectbox('Explain one of my alerts',range(len(flagged)),format_func=lambda i:str(flagged.iloc[i]['name'])+' | '+str(flagged.iloc[i].pid)); explain(flagged.iloc[i])
elif page=='Reports & privacy':
    import pandas as pd
    from guard_v4 import history
    st.title('Reports and privacy')
    st.write('Scan results stay in this session unless you export them. Optional history stores only scan totals. Older versions may have saved command lines in logs/alerts.csv.')
    if 'result' in S:
        df=S.result; summary(df)
        st.download_button('Download scan CSV',df.drop(columns=['cmdline'],errors='ignore').to_csv(index=False),'guard_scan.csv','text/csv')
        report='FilelessGuard AI — research scan\n'+S.scan_time+'\n'+ '\n'.join(f'{v}: {int((df.verdict==k).sum())}' for k,v in labels.items())+'\nNot confirmed infections. Synthetic model; hybrid rules not validated.'
        st.download_button('Download simple text report',report,'guard_report.txt','text/plain')
    try:
        h=history()
        if h: st.dataframe(pd.DataFrame(h),width='stretch'); st.line_chart(pd.DataFrame(h).set_index('Time')[['Needs review','High risk']])
    except Exception as e: st.warning(f'History unavailable: {e}')
    if st.checkbox('Confirm deletion of V4 saved scan totals') and st.button('Delete saved totals'):
        Path('logs/guard_v4_history.jsonl').unlink(missing_ok=True); st.rerun()
    st.caption('This does not delete older alert logs or downloaded reports.')
else:
    st.title('About this project'); st.write('Intelligent Fileless Malware Detection and Suspicious Process Monitoring System')
    st.subheader('How it works'); st.graphviz_chart('digraph { rankdir=TB; node [shape=box style=rounded]; "Running applications" -> "Collect process information" -> "Extract behavior features" -> "Random Forest model" -> "Risk report"; }')
    a,b=st.columns(2)
    with a: st.subheader('Advantages'); st.markdown('- Local monitoring\n- Explainable indicators\n- Visual reports\n- Low-cost implementation')
    with b: st.subheader('Limitations'); st.markdown('- Synthetic training data\n- False positives and missed threats\n- No direct memory inspection\n- Not an antivirus replacement')
    p=Path('models/metrics.json')
    if p.exists():
        m=json.loads(p.read_text()); st.subheader('Model evaluation'); st.warning('Synthetic Random Forest test results only — not hybrid or real-world detection accuracy.')
        cols=st.columns(4)
        for c,k in zip(cols,['accuracy','precision','recall','f1']): c.metric(k.title(),f'{m[k]:.2%}')
        import pandas as pd
        st.bar_chart(pd.DataFrame({'Metric':['Accuracy','Precision','Recall','F1'],'Percent':[100*m[k] for k in ['accuracy','precision','recall','f1']]}).set_index('Metric'))
        for c,f in zip(st.columns(2),['confusion_matrix.png','feature_importance.png']):
            if Path('models',f).exists(): c.image(str(Path('models',f)),caption=f.replace('_',' ').replace('.png','').title())
