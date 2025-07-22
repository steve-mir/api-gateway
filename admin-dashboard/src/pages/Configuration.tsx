import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Editor } from '@monaco-editor/react'
import { 
  Save, 
  RefreshCw, 
  Download, 
  Upload, 
  CheckCircle, 
  XCircle, 
  History,
  Eye,
  Edit
} from 'lucide-react'
import toast from 'react-hot-toast'
import { adminApi } from '@/lib/api'
import { GatewayConfig } from '@/types'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'

export function Configuration() {
  const [activeTab, setActiveTab] = useState<'editor' | 'visual'>('visual')
  const [configText, setConfigText] = useState('')
  const [isValidating, setIsValidating] = useState(false)
  const [validationResult, setValidationResult] = useState<{ valid: boolean; errors: string[] } | null>(null)
  const [showBackupModal, setShowBackupModal] = useState(false)
  const [showHistoryModal, setShowHistoryModal] = useState(false)

  const queryClient = useQueryClient()

  const { data: configData, isLoading } = useQuery({
    queryKey: ['configuration'],
    queryFn: () => adminApi.getConfiguration(),
    onSuccess: (data) => {
      setConfigText(JSON.stringify(data.data.config, null, 2))
    },
  })

  const { data: auditHistory } = useQuery({
    queryKey: ['config-audit'],
    queryFn: () => adminApi.getAuditHistory({ change_type: 'ConfigurationChange', limit: 20 }),
  })

  const updateConfigMutation = useMutation({
    mutationFn: (config: GatewayConfig) => adminApi.updateConfiguration({
      config,
      changed_by: 'admin',
      description: 'Configuration updated via admin dashboard',
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['configuration'] })
      toast.success('Configuration updated successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to update configuration')
    },
  })

  const validateConfigMutation = useMutation({
    mutationFn: (config: GatewayConfig) => adminApi.validateConfiguration(config),
    onSuccess: (data) => {
      setValidationResult(data.data)
      if (data.data.valid) {
        toast.success('Configuration is valid')
      } else {
        toast.error('Configuration validation failed')
      }
    },
    onError: () => {
      toast.error('Failed to validate configuration')
    },
  })

  const backupConfigMutation = useMutation({
    mutationFn: (data: any) => adminApi.backupConfiguration(data),
    onSuccess: () => {
      toast.success('Configuration backup created successfully')
      setShowBackupModal(false)
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to create backup')
    },
  })

  const handleSave = async () => {
    try {
      const config = JSON.parse(configText)
      updateConfigMutation.mutate(config)
    } catch (error) {
      toast.error('Invalid JSON format')
    }
  }

  const handleValidate = async () => {
    try {
      setIsValidating(true)
      const config = JSON.parse(configText)
      await validateConfigMutation.mutateAsync(config)
    } catch (error) {
      toast.error('Invalid JSON format')
      setValidationResult({ valid: false, errors: ['Invalid JSON format'] })
    } finally {
      setIsValidating(false)
    }
  }

  const handleExport = () => {
    const blob = new Blob([configText], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `gateway-config-${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = (e) => {
        const content = e.target?.result as string
        try {
          const config = JSON.parse(content)
          setConfigText(JSON.stringify(config, null, 2))
          toast.success('Configuration imported successfully')
        } catch (error) {
          toast.error('Invalid JSON file')
        }
      }
      reader.readAsText(file)
    }
  }

  const handleBackup = (description: string) => {
    backupConfigMutation.mutate({
      description,
      created_by: 'admin',
    })
  }

  const config = configData?.data?.config

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Configuration</h1>
          <p className="text-muted-foreground">
            Manage gateway configuration with validation and diff view
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowHistoryModal(true)}>
            <History className="h-4 w-4 mr-2" />
            History
          </Button>
          <Button variant="outline" size="sm" onClick={() => setShowBackupModal(true)}>
            <Download className="h-4 w-4 mr-2" />
            Backup
          </Button>
          <label className="cursor-pointer">
            <Button variant="outline" size="sm" asChild>
              <span>
                <Upload className="h-4 w-4 mr-2" />
                Import
              </span>
            </Button>
            <input
              type="file"
              accept=".json"
              onChange={handleImport}
              className="hidden"
            />
          </label>
        </div>
      </div>

      {/* Status Card */}
      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-600" />
              <span className="font-medium">Configuration Status: Active</span>
            </div>
            <div className="text-sm text-muted-foreground">
              Last modified: {configData?.data?.last_modified ? 
                new Date(configData.data.last_modified).toLocaleString() : 
                'Never'
              }
            </div>
          </div>
          <div className="flex items-center gap-2">
            {validationResult && (
              <div className={`flex items-center gap-1 px-2 py-1 rounded text-sm ${
                validationResult.valid 
                  ? 'bg-green-100 text-green-800' 
                  : 'bg-red-100 text-red-800'
              }`}>
                {validationResult.valid ? (
                  <CheckCircle className="h-4 w-4" />
                ) : (
                  <XCircle className="h-4 w-4" />
                )}
                {validationResult.valid ? 'Valid' : 'Invalid'}
              </div>
            )}
          </div>
        </div>
      </Card>

      {/* Tab Navigation */}
      <div className="border-b border-border">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('visual')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'visual'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground'
            }`}
          >
            <Eye className="h-4 w-4 inline mr-2" />
            Visual Editor
          </button>
          <button
            onClick={() => setActiveTab('editor')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'editor'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground'
            }`}
          >
            <Edit className="h-4 w-4 inline mr-2" />
            JSON Editor
          </button>
        </nav>
      </div>

      {/* Content */}
      {activeTab === 'visual' ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Server Configuration */}
          <Card className="p-6">
            <h3 className="text-lg font-medium mb-4">Server Configuration</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Host</label>
                <input
                  type="text"
                  value={config?.server?.host || ''}
                  readOnly
                  className="w-full px-3 py-2 border border-input rounded-md bg-muted text-foreground"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Port</label>
                <input
                  type="number"
                  value={config?.server?.port || ''}
                  readOnly
                  className="w-full px-3 py-2 border border-input rounded-md bg-muted text-foreground"
                />
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config?.server?.tls?.enabled || false}
                  readOnly
                  className="rounded border-input"
                />
                <label className="text-sm font-medium">TLS Enabled</label>
              </div>
            </div>
          </Card>

          {/* Routes */}
          <Card className="p-6">
            <h3 className="text-lg font-medium mb-4">Routes ({config?.routes?.length || 0})</h3>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {config?.routes?.map((route, index) => (
                <div key={index} className="p-3 border border-border rounded-md">
                  <div className="font-medium">{route.path}</div>
                  <div className="text-sm text-muted-foreground">
                    {route.methods?.join(', ')} → {route.upstream}
                  </div>
                </div>
              )) || (
                <div className="text-center py-4 text-muted-foreground">
                  No routes configured
                </div>
              )}
            </div>
          </Card>

          {/* Upstreams */}
          <Card className="p-6">
            <h3 className="text-lg font-medium mb-4">
              Upstreams ({Object.keys(config?.upstreams || {}).length})
            </h3>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {Object.entries(config?.upstreams || {}).map(([name, upstream]) => (
                <div key={name} className="p-3 border border-border rounded-md">
                  <div className="font-medium">{name}</div>
                  <div className="text-sm text-muted-foreground">
                    {upstream.discovery?.type} • {upstream.load_balancer?.algorithm}
                  </div>
                </div>
              )) || (
                <div className="text-center py-4 text-muted-foreground">
                  No upstreams configured
                </div>
              )}
            </div>
          </Card>

          {/* Middleware */}
          <Card className="p-6">
            <h3 className="text-lg font-medium mb-4">Middleware</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span>Authentication</span>
                <span className={`px-2 py-1 text-xs rounded ${
                  config?.middleware?.auth?.enabled 
                    ? 'bg-green-100 text-green-800' 
                    : 'bg-gray-100 text-gray-800'
                }`}>
                  {config?.middleware?.auth?.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Rate Limiting</span>
                <span className={`px-2 py-1 text-xs rounded ${
                  config?.middleware?.rate_limiting?.enabled 
                    ? 'bg-green-100 text-green-800' 
                    : 'bg-gray-100 text-gray-800'
                }`}>
                  {config?.middleware?.rate_limiting?.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>CORS</span>
                <span className={`px-2 py-1 text-xs rounded ${
                  config?.middleware?.cors?.enabled 
                    ? 'bg-green-100 text-green-800' 
                    : 'bg-gray-100 text-gray-800'
                }`}>
                  {config?.middleware?.cors?.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
            </div>
          </Card>
        </div>
      ) : (
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium">JSON Configuration</h3>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleValidate}
                disabled={isValidating}
              >
                {isValidating ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <CheckCircle className="h-4 w-4 mr-2" />
                )}
                Validate
              </Button>
              <Button variant="outline" size="sm" onClick={handleExport}>
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
              <Button
                onClick={handleSave}
                disabled={updateConfigMutation.isPending}
              >
                {updateConfigMutation.isPending ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Save className="h-4 w-4 mr-2" />
                )}
                Save
              </Button>
            </div>
          </div>

          {/* Validation Errors */}
          {validationResult && !validationResult.valid && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-md">
              <h4 className="font-medium text-red-800 mb-2">Validation Errors:</h4>
              <ul className="list-disc list-inside text-sm text-red-700">
                {validationResult.errors.map((error, index) => (
                  <li key={index}>{error}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="border border-border rounded-md overflow-hidden">
            <Editor
              height="600px"
              defaultLanguage="json"
              value={configText}
              onChange={(value) => setConfigText(value || '')}
              theme="vs-dark"
              options={{
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                fontSize: 14,
                wordWrap: 'on',
                formatOnPaste: true,
                formatOnType: true,
              }}
            />
          </div>
        </Card>
      )}

      {/* Backup Modal */}
      <Modal
        isOpen={showBackupModal}
        onClose={() => setShowBackupModal(false)}
        title="Create Configuration Backup"
      >
        <BackupForm
          onSubmit={handleBackup}
          onCancel={() => setShowBackupModal(false)}
          isLoading={backupConfigMutation.isPending}
        />
      </Modal>

      {/* History Modal */}
      <Modal
        isOpen={showHistoryModal}
        onClose={() => setShowHistoryModal(false)}
        title="Configuration History"
        size="lg"
      >
        <ConfigHistory
          history={auditHistory?.data?.records || []}
          onClose={() => setShowHistoryModal(false)}
        />
      </Modal>
    </div>
  )
}

// Backup Form Component
function BackupForm({ 
  onSubmit, 
  onCancel, 
  isLoading 
}: { 
  onSubmit: (description: string) => void
  onCancel: () => void
  isLoading: boolean 
}) {
  const [description, setDescription] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(description || 'Manual backup')
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium mb-1">
          Description
        </label>
        <input
          type="text"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Backup description..."
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>
      <div className="flex justify-end space-x-2">
        <Button type="button" variant="outline" onClick={onCancel} disabled={isLoading}>
          Cancel
        </Button>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? 'Creating...' : 'Create Backup'}
        </Button>
      </div>
    </form>
  )
}

// Config History Component
function ConfigHistory({ 
  history, 
  onClose 
}: { 
  history: any[]
  onClose: () => void 
}) {
  return (
    <div className="space-y-4">
      <div className="max-h-96 overflow-y-auto">
        {history.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            No configuration history found
          </div>
        ) : (
          <div className="space-y-3">
            {history.map((record, index) => (
              <div key={index} className="p-3 border border-border rounded-md">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium">{record.action}</span>
                  <span className="text-sm text-muted-foreground">
                    {new Date(record.timestamp).toLocaleString()}
                  </span>
                </div>
                <div className="text-sm text-muted-foreground">
                  By: {record.user_id || 'System'}
                </div>
                {record.details?.description && (
                  <div className="text-sm mt-1">{record.details.description}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="flex justify-end">
        <Button onClick={onClose}>Close</Button>
      </div>
    </div>
  )
}