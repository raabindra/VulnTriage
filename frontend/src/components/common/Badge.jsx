import clsx from 'clsx'

const SEVERITY_STYLES = {
  Critical:      'bg-red-100 text-red-800',
  High:          'bg-orange-100 text-orange-800',
  Medium:        'bg-amber-100 text-amber-800',
  Low:           'bg-green-100 text-green-800',
  Informational: 'bg-gray-100 text-gray-700',
  Unknown:       'bg-gray-100 text-gray-500',
}

const CLASSIFICATION_STYLES = {
  'Confirmed':               'bg-green-100 text-green-800',
  'Needs Manual Verification':'bg-amber-100 text-amber-800',
  'Not Confirmed':           'bg-red-100 text-red-800',
  'Unclassified':            'bg-gray-100 text-gray-500',
}

const PRIORITY_STYLES = {
  Critical: 'bg-red-100 text-red-800',
  High:     'bg-orange-100 text-orange-800',
  Medium:   'bg-amber-100 text-amber-800',
  Low:      'bg-green-100 text-green-800',
}

const STATUS_STYLES = {
  completed:  'bg-green-100 text-green-800',
  processing: 'bg-blue-100 text-blue-800',
  pending:    'bg-gray-100 text-gray-600',
  failed:     'bg-red-100 text-red-800',
}

export function SeverityBadge({ severity }) {
  return (
    <span className={clsx('badge', SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.Unknown)}>
      {severity ?? 'Unknown'}
    </span>
  )
}

export function ClassificationBadge({ classification }) {
  const label = classification ?? 'Unclassified'
  return (
    <span className={clsx('badge', CLASSIFICATION_STYLES[label] ?? CLASSIFICATION_STYLES.Unclassified)}>
      {label}
    </span>
  )
}

export function PriorityBadge({ priority }) {
  return (
    <span className={clsx('badge', PRIORITY_STYLES[priority] ?? 'bg-gray-100 text-gray-500')}>
      {priority ?? '—'}
    </span>
  )
}

export function StatusBadge({ status }) {
  return (
    <span className={clsx('badge', STATUS_STYLES[status] ?? 'bg-gray-100 text-gray-500')}>
      {status}
    </span>
  )
}
