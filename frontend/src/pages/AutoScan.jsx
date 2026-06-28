import { useEffect, useState } from 'react'
import { BoltIcon, CheckCircleIcon, XCircleIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline'
import { getScanners, runAutoScan } from '../services/upload'
import { Spinner } from '../components/common/Loading'

const SCANNER_META = {
  zap:    { label: 'OWASP ZAP',  note: 'Spider + active scan (headless)' },
  nuclei: { label: 'Nuclei',     note: 'Template-based, fast' },
  // Nessus is not auto-launched (Essentials/Pro block scan creation via API).
  // Use it by exporting a .nessus report and uploading it on the Upload page.
}

export default function AutoScan() {
  const [target, setTarget]   = useState('')
  const [avail, setAvail]     = useState({})
  const [picked, setPicked]   = useState({ zap: true, nuclei: true, nessus: false })
  const [authorise, setAuthorise] = useState(false)
  const [searchExploits, setSearchExploits] = useState(false)
  const [runPoc, setRunPoc]   = useState(false)
  const [pocScope, setPocScope] = useState('')
  const [running, setRunning] = useState(false)
  const [error, setError]     = useState('')
  const [result, setResult]   = useState(null)

  useEffect(() => {
    getScanners().then(({ data }) => setAvail(data)).catch(() => {})
  }, [])

  const chosen = Object.keys(picked).filter((s) => picked[s])
  const canRun = target.trim() && authorise && chosen.length > 0 && !running

  async function start() {
    setError(''); setResult(null); setRunning(true)
    try {
      const { data } = await runAutoScan({
        target: target.trim(), scanners: chosen, authorise,
        searchExploits, runPoc, pocScope,
      })
      setResult(data.autoscan_results)
    } catch (e) {
      setError(e.response?.data?.error || 'Auto scan failed')
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
          <BoltIcon className="h-6 w-6 text-primary-600" /> Auto Scan
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Optional orchestration: VulnTriage runs the selected scanners against a target,
          then ingests and triages the combined results automatically.
        </p>
      </div>

      {/* Authorisation warning */}
      <div className="card p-4 bg-amber-50 border-amber-200">
        <div className="flex gap-2 text-amber-800">
          <ExclamationTriangleIcon className="h-5 w-5 shrink-0" />
          <p className="text-sm">
            Active scanning is intrusive. Only scan systems you own or have explicit
            written permission to test.
          </p>
        </div>
      </div>

      <div className="card p-6 space-y-5">
        {/* Target */}
        <div>
          <label className="text-sm font-semibold text-gray-700">Target URL</label>
          <input
            type="text" value={target} onChange={(e) => setTarget(e.target.value)}
            placeholder="http://localhost:3000"
            className="input mt-1 w-full"
          />
        </div>

        {/* Scanner selection */}
        <div>
          <label className="text-sm font-semibold text-gray-700">Scanners</label>
          <div className="mt-2 space-y-2">
            {Object.entries(SCANNER_META).map(([key, meta]) => {
              const a = avail[key]
              const usable = a?.available
              return (
                <label key={key}
                  className={`flex items-center gap-3 p-3 rounded-lg border ${usable ? 'border-gray-200 hover:bg-gray-50 cursor-pointer' : 'border-gray-100 bg-gray-50 opacity-60'}`}>
                  <input
                    type="checkbox" disabled={!usable}
                    checked={!!picked[key] && usable}
                    onChange={(e) => setPicked((p) => ({ ...p, [key]: e.target.checked }))}
                  />
                  <div className="flex-1">
                    <p className="text-sm font-medium text-gray-800">{meta.label}</p>
                    <p className="text-xs text-gray-400">
                      {usable ? meta.note : (a?.reason || 'unavailable')}
                    </p>
                  </div>
                  {usable
                    ? <CheckCircleIcon className="h-4 w-4 text-green-500" />
                    : <XCircleIcon className="h-4 w-4 text-gray-300" />}
                </label>
              )
            })}
          </div>
          <p className="text-xs text-gray-400 mt-2">
            Using Nessus? Run it in the Nessus UI, export the <code>.nessus</code> report,
            and upload it on the Upload page — it flows through the same triage pipeline.
          </p>
        </div>

        {/* Post-scan options */}
        <div className="flex flex-wrap gap-4 text-sm">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={searchExploits} onChange={(e) => setSearchExploits(e.target.checked)} />
            Exploit lookup (searchsploit)
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={runPoc} onChange={(e) => setRunPoc(e.target.checked)} />
            PoC validation
          </label>
        </div>
        {runPoc && (
          <input
            type="text" value={pocScope} onChange={(e) => setPocScope(e.target.value)}
            placeholder="PoC scope (optional): host1, host2"
            className="input w-full text-sm"
          />
        )}

        {/* Authorisation + run */}
        <label className="flex items-center gap-2 text-sm border-t border-gray-100 pt-4">
          <input type="checkbox" checked={authorise} onChange={(e) => setAuthorise(e.target.checked)} />
          <span>I am authorised to actively scan this target.</span>
        </label>

        <button onClick={start} disabled={!canRun}
          className="btn-primary w-full justify-center disabled:opacity-50">
          {running ? <><Spinner size="sm" /> Scanning… (this can take several minutes)</> : 'Start Auto Scan'}
        </button>
      </div>

      {error && (
        <div className="card p-3 bg-red-50 border-red-200 text-red-700 text-sm flex items-center gap-2">
          <XCircleIcon className="h-4 w-4 shrink-0" /> {error}
        </div>
      )}

      {result && (
        <div className="card p-5 space-y-3">
          <h2 className="text-sm font-semibold text-gray-700">Auto Scan Complete</h2>
          <div className="space-y-1 text-sm">
            {Object.entries(result.scanners).map(([name, info]) => (
              <div key={name} className="flex items-center gap-2">
                {info.status === 'ok'
                  ? <CheckCircleIcon className="h-4 w-4 text-green-500" />
                  : <XCircleIcon className="h-4 w-4 text-amber-500" />}
                <span className="capitalize font-medium">{name}</span>
                <span className="text-gray-500">
                  {info.status === 'ok' ? `${info.findings} findings` : `${info.status} — ${info.reason}`}
                </span>
              </div>
            ))}
          </div>
          <div className="text-sm text-gray-600 border-t border-gray-100 pt-3">
            {result.confidence_scored} findings scored
            {result.exploit_search?.available ? `, ${result.exploit_search.total_exploits} exploit(s) found` : ''}
            {result.poc_validated != null ? `, ${result.poc_validated} PoC checks` : ''}
            {result.report_id ? `, report #${result.report_id} generated` : ''}.
          </div>
        </div>
      )}
    </div>
  )
}
