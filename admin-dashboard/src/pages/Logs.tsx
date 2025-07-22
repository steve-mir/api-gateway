import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { 
  Search, 
  Filter, 
  Download, 
  RefreshCw, 
  Calendar,
  AlertCircle,
  Info,
  AlertTriangle,
  XCircle,
  CheckCircle,
  Eye,
  Trash2
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { adminApi } from '@/lib/api'
import { AuditLogEntry, AuditEventType, AuditOutcome } from '@/types'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'

export function Logs() {
  const [activeTab, setActiveTab] = useState<'system' | 'audit'>('system')
  const [searchTerm, setSearchTerm] = useState('')
  const [levelFilter, setLevelFilter] = useState<string>('all')
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('all')
  const [outcomeFilter, setOutcomeFilter] = useState<string>('all')
  const [selectedLog, setSelectedLog] = useState<any>(null)
  const [showClearModal, setShowClearModal] = useState(false)

  // System logs query (mock implementation)
  const { data: systemLogs, refetch: refetchSystemLogs } = useQuery({
    queryKey: ['system-logs', levelFilter, searchTerm],
    queryFn: () => adminApi.queryLogs({
      level: levelFilter !== 'all' ? levelFilter : undefined,
      component: searchTerm || undefined,
      limit: 100,
    }),
    refetchInterval: 30000,
  })

  // Audit logs query
  const { data: auditLogs, refetch: refetchAuditLogs } = useQuery({
    queryKey: ['audit-logs', eventTypeFilter, outcomeFilter],
    queryFn: () => adminApi.queryAuditLogs({
      event_type: eventTypeFilter !== 'all' ? eventTypeFilter : undefined,
      outcome: outcomeFilter !== 'all' ? outcomeFilter : undefined,
      limit: 100,
    }),
    refetchInterval: 30000,
  })

  const { data: auditStats } = useQuery({
    queryKey: ['audit-statistics'],
    queryFn: () => adminApi.getAuditStatistics(),
    refetchInterval: 60000,
  })

  const getLevelIcon = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'error':
        return <XCircle className="h-4 w-4 text-red-600" />
      case 'warn':
        return <AlertTriangle className="h-4 w-4 text-yellow-600" />
      case 'info':
        return <Info className="h-4 w-4 text-blue-600" />
      case 'debug':
        return <AlertCircle className="h-4 w-4 text-gray-600" />
      default:
        return <Info className="h-4 w-4 text-gray-600" />
    }
  }

  const getOutcomeIcon = (outcome: AuditOutcome) => {
    switch (outcome) {
      case AuditOutcome.Success:
        return <CheckCircle className="h-4 w-4 text-green-600" />
      case AuditOutcome.Failure:
        return <XCircle className="h-4 w-4 text-red-600" />
      case AuditOutcome.Denied:
        return <AlertTriangle className="h-4 w-4 text-yellow-600" />
      default:
        return <AlertCircle className="h-4 w-4 text-gray-600" />
    }
  }

  const handleExportLogs = () => {
    const logs = activeTab === 'system' ? systemLogs?.data?.logs : auditLogs?.data?.logs
    if (!logs) return

    const csvData = logs.map((log: any) => {
      if (activeTab === 'system') {
        return `${log.timestamp},${log.level},${log.component},${log.message}`
      } else {
        return `${log.timestamp},${log.event_type},${log.user_id || ''},${log.action},${log.outcome}`
      }
    }).join('\n')

    const headers = activeTab === 'system' 
      ? 'Timestamp,Level,Component,Message\n'
      : 'Timestamp,Event Type,User,Action,Outcome\n'

    const blob = new Blob([headers + csvData], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${activeTab}-logs-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleClearAuditLogs = () => {
    // In a real implementation, this would call the API
    setShowClearModal(false)
    refetchAuditLogs()
  }

  const currentLogs = activeTab === 'system' ? systemLogs?.data?.logs : auditLogs?.data?.logs

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Logs</h1>
          <p className="text-muted-foreground">
            Real-time log viewer with filtering and search capabilities
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={activeTab === 'system' ? refetchSystemLogs : refetchAuditLogs}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={handleExportLogs}>
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
          {activeTab === 'audit' && (
            <Button 
              variant="outline" 
              size="sm" 
              onClick={() => setShowClearModal(true)}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Clear
            </Button>
          )}
        </div>
      </div>

      {/* Stats Cards */}
      {activeTab === 'audit' && auditStats?.data && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card className="p-4">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <AlertCircle className="h-6 w-6 text-blue-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-muted-foreground">Total Events</p>
                <p className="text-2xl font-bold">{auditStats.data.total_events}</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <CheckCircle className="h-6 w-6 text-green-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-muted-foreground">Success</p>
                <p className="text-2xl font-bold">
                  {auditStats.data.outcome_counts?.Success || 0}
                </p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <XCircle className="h-6 w-6 text-red-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-muted-foreground">Failures</p>
                <p className="text-2xl font-bold">
                  {auditStats.data.outcome_counts?.Failure || 0}
                </p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Calendar className="h-6 w-6 text-purple-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-muted-foreground">Last Hour</p>
                <p className="text-2xl font-bold">{auditStats.data.recent_events_last_hour}</p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="border-b border-border">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('system')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'system'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground'
            }`}
          >
            System Logs
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'audit'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground'
            }`}
          >
            Audit Logs
          </button>
        </nav>
      </div>

      {/* Filters */}
      <Card className="p-4">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <input
                type="text"
                placeholder={activeTab === 'system' ? 'Search logs...' : 'Search audit logs...'}
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            {activeTab === 'system' ? (
              <select
                value={levelFilter}
                onChange={(e) => setLevelFilter(e.target.value)}
                className="px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="all">All Levels</option>
                <option value="error">Error</option>
                <option value="warn">Warning</option>
                <option value="info">Info</option>
                <option value="debug">Debug</option>
              </select>
            ) : (
              <>
                <select
                  value={eventTypeFilter}
                  onChange={(e) => setEventTypeFilter(e.target.value)}
                  className="px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="all">All Events</option>
                  <option value="Authentication">Authentication</option>
                  <option value="Authorization">Authorization</option>
                  <option value="AdminOperation">Admin Operation</option>
                  <option value="ConfigurationChange">Configuration Change</option>
                  <option value="SecurityViolation">Security Violation</option>
                </select>
                <select
                  value={outcomeFilter}
                  onChange={(e) => setOutcomeFilter(e.target.value)}
                  className="px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="all">All Outcomes</option>
                  <option value="Success">Success</option>
                  <option value="Failure">Failure</option>
                  <option value="Denied">Denied</option>
                </select>
              </>
            )}
          </div>
        </div>
      </Card>

      {/* Logs Table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Status</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Timestamp</th>
                {activeTab === 'system' ? (
                  <>
                    <th className="text-left py-3 px-4 font-medium text-muted-foreground">Level</th>
                    <th className="text-left py-3 px-4 font-medium text-muted-foreground">Component</th>
                    <th className="text-left py-3 px-4 font-medium text-muted-foreground">Message</th>
                  </>
                ) : (
                  <>
                    <th className="text-left py-3 px-4 font-medium text-muted-foreground">Event Type</th>
                    <th className="text-left py-3 px-4 font-medium text-muted-foreground">User</th>
                    <th className="text-left py-3 px-4 font-medium text-muted-foreground">Action</th>
                    <th className="text-left py-3 px-4 font-medium text-muted-foreground">Resource</th>
                  </>
                )}
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {!currentLogs || currentLogs.length === 0 ? (
                <tr>
                  <td colSpan={activeTab === 'system' ? 6 : 7} className="text-center py-8 text-muted-foreground">
                    No logs found
                  </td>
                </tr>
              ) : (
                currentLogs.map((log: any, index: number) => (
                  <tr key={index} className="border-b border-border hover:bg-muted/50">
                    <td className="py-3 px-4">
                      {activeTab === 'system' 
                        ? getLevelIcon(log.level) 
                        : getOutcomeIcon(log.outcome)
                      }
                    </td>
                    <td className="py-3 px-4 text-sm">
                      {formatDistanceToNow(new Date(log.timestamp), { addSuffix: true })}
                    </td>
                    {activeTab === 'system' ? (
                      <>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                            log.level === 'error' ? 'bg-red-100 text-red-800' :
                            log.level === 'warn' ? 'bg-yellow-100 text-yellow-800' :
                            log.level === 'info' ? 'bg-blue-100 text-blue-800' :
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {log.level?.toUpperCase() || 'INFO'}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-sm">{log.component || 'system'}</td>
                        <td className="py-3 px-4 text-sm max-w-md truncate">
                          {log.message || 'Log message placeholder'}
                        </td>
                      </>
                    ) : (
                      <>
                        <td className="py-3 px-4">
                          <span className="px-2 py-1 text-xs font-medium bg-secondary text-secondary-foreground rounded">
                            {log.event_type}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-sm">{log.user_id || 'System'}</td>
                        <td className="py-3 px-4 text-sm">{log.action}</td>
                        <td className="py-3 px-4 text-sm">{log.resource}</td>
                      </>
                    )}
                    <td className="py-3 px-4">
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="p-1 hover:bg-muted rounded"
                        title="View details"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Log Details Modal */}
      <Modal
        isOpen={!!selectedLog}
        onClose={() => setSelectedLog(null)}
        title="Log Details"
        size="lg"
      >
        {selectedLog && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-1">Timestamp</label>
                <div className="text-sm">{new Date(selectedLog.timestamp).toLocaleString()}</div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">
                  {activeTab === 'system' ? 'Level' : 'Outcome'}
                </label>
                <div className="text-sm">
                  {activeTab === 'system' ? selectedLog.level : selectedLog.outcome}
                </div>
              </div>
            </div>
            
            {activeTab === 'audit' && (
              <>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Event Type</label>
                    <div className="text-sm">{selectedLog.event_type}</div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">User</label>
                    <div className="text-sm">{selectedLog.user_id || 'System'}</div>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Action</label>
                    <div className="text-sm">{selectedLog.action}</div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Resource</label>
                    <div className="text-sm">{selectedLog.resource}</div>
                  </div>
                </div>
                {selectedLog.correlation_id && (
                  <div>
                    <label className="block text-sm font-medium mb-1">Correlation ID</label>
                    <div className="text-sm font-mono">{selectedLog.correlation_id}</div>
                  </div>
                )}
                {selectedLog.details && Object.keys(selectedLog.details).length > 0 && (
                  <div>
                    <label className="block text-sm font-medium mb-1">Details</label>
                    <pre className="text-xs bg-muted p-3 rounded-md overflow-auto max-h-40">
                      {JSON.stringify(selectedLog.details, null, 2)}
                    </pre>
                  </div>
                )}
              </>
            )}
            
            <div className="flex justify-end">
              <Button onClick={() => setSelectedLog(null)}>Close</Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Clear Audit Logs Modal */}
      <Modal
        isOpen={showClearModal}
        onClose={() => setShowClearModal(false)}
        title="Clear Audit Logs"
      >
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Are you sure you want to clear all audit logs? This action cannot be undone.
          </p>
          <div className="flex justify-end space-x-2">
            <Button variant="outline" onClick={() => setShowClearModal(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleClearAuditLogs}>
              Clear Logs
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}