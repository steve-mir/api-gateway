import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Plus, 
  Bell, 
  BellOff, 
  Edit, 
  Trash2, 
  Play, 
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp
} from 'lucide-react'
import toast from 'react-hot-toast'
import { adminApi } from '@/lib/api'
import { AlertRule, AlertCondition } from '@/types'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import { AlertRuleForm } from '@/components/forms/AlertRuleForm'

export function Alerts() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingAlert, setEditingAlert] = useState<AlertRule | null>(null)
  const [selectedAlert, setSelectedAlert] = useState<AlertRule | null>(null)

  const queryClient = useQueryClient()

  const { data: alertRules, isLoading } = useQuery({
    queryKey: ['alert-rules'],
    queryFn: () => adminApi.getAlertRules(),
    refetchInterval: 30000,
  })

  const createAlertMutation = useMutation({
    mutationFn: adminApi.createAlertRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-rules'] })
      setShowCreateModal(false)
      toast.success('Alert rule created successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to create alert rule')
    },
  })

  const updateAlertMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => 
      adminApi.updateAlertRule(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-rules'] })
      setEditingAlert(null)
      toast.success('Alert rule updated successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to update alert rule')
    },
  })

  const deleteAlertMutation = useMutation({
    mutationFn: (id: string) => adminApi.deleteAlertRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-rules'] })
      toast.success('Alert rule deleted successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to delete alert rule')
    },
  })

  const triggerAlertMutation = useMutation({
    mutationFn: (id: string) => adminApi.triggerAlertRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-rules'] })
      toast.success('Alert rule triggered successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to trigger alert rule')
    },
  })

  const rules = alertRules?.data || []
  const activeRules = rules.filter((rule: AlertRule) => rule.enabled)
  const recentlyTriggered = rules.filter((rule: AlertRule) => 
    rule.last_triggered && 
    new Date(rule.last_triggered).getTime() > Date.now() - 24 * 60 * 60 * 1000
  )

  const handleCreateAlert = (data: any) => {
    createAlertMutation.mutate(data)
  }

  const handleUpdateAlert = (data: any) => {
    if (editingAlert) {
      updateAlertMutation.mutate({ id: editingAlert.id, data })
    }
  }

  const handleDeleteAlert = (id: string) => {
    if (confirm('Are you sure you want to delete this alert rule?')) {
      deleteAlertMutation.mutate(id)
    }
  }

  const handleToggleAlert = (rule: AlertRule) => {
    updateAlertMutation.mutate({
      id: rule.id,
      data: { enabled: !rule.enabled }
    })
  }

  const getConditionText = (condition: AlertCondition) => {
    switch (condition) {
      case AlertCondition.GreaterThan:
        return '>'
      case AlertCondition.LessThan:
        return '<'
      case AlertCondition.GreaterThanOrEqual:
        return '>='
      case AlertCondition.LessThanOrEqual:
        return '<='
      case AlertCondition.Equal:
        return '='
      case AlertCondition.NotEqual:
        return '!='
      default:
        return '?'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Alert Management</h1>
          <p className="text-muted-foreground">
            Configure and manage alert rules for monitoring gateway metrics
          </p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Create Alert Rule
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4">
          <div className="flex items-center">
            <Bell className="h-8 w-8 text-blue-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Total Rules</p>
              <p className="text-2xl font-bold">{rules.length}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center">
            <CheckCircle className="h-8 w-8 text-green-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Active Rules</p>
              <p className="text-2xl font-bold">{activeRules.length}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center">
            <AlertTriangle className="h-8 w-8 text-yellow-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Recently Triggered</p>
              <p className="text-2xl font-bold">{recentlyTriggered.length}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center">
            <BellOff className="h-8 w-8 text-gray-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Disabled Rules</p>
              <p className="text-2xl font-bold">{rules.length - activeRules.length}</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Alert Rules Table */}
      <Card>
        <div className="p-6">
          <h3 className="text-lg font-medium mb-4">Alert Rules</h3>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 font-medium text-muted-foreground">Status</th>
                  <th className="text-left py-3 px-4 font-medium text-muted-foreground">Name</th>
                  <th className="text-left py-3 px-4 font-medium text-muted-foreground">Metric</th>
                  <th className="text-left py-3 px-4 font-medium text-muted-foreground">Condition</th>
                  <th className="text-left py-3 px-4 font-medium text-muted-foreground">Last Triggered</th>
                  <th className="text-left py-3 px-4 font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={6} className="text-center py-8">
                      <div className="spinner w-6 h-6 mx-auto"></div>
                    </td>
                  </tr>
                ) : rules.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center py-8 text-muted-foreground">
                      No alert rules configured
                    </td>
                  </tr>
                ) : (
                  rules.map((rule: AlertRule) => (
                    <tr key={rule.id} className="border-b border-border hover:bg-muted/50">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          {rule.enabled ? (
                            <CheckCircle className="h-4 w-4 text-green-600" />
                          ) : (
                            <BellOff className="h-4 w-4 text-gray-600" />
                          )}
                          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                            rule.enabled 
                              ? 'bg-green-100 text-green-800' 
                              : 'bg-gray-100 text-gray-800'
                          }`}>
                            {rule.enabled ? 'Active' : 'Disabled'}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div>
                          <div className="font-medium">{rule.name}</div>
                          {rule.description && (
                            <div className="text-sm text-muted-foreground">{rule.description}</div>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-sm">{rule.metric_name}</td>
                      <td className="py-3 px-4">
                        <span className="font-mono text-sm">
                          {getConditionText(rule.condition)} {rule.threshold}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm">
                        {rule.last_triggered ? (
                          <div className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {new Date(rule.last_triggered).toLocaleString()}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">Never</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleToggleAlert(rule)}
                            className="p-1 hover:bg-muted rounded"
                            title={rule.enabled ? 'Disable alert' : 'Enable alert'}
                          >
                            {rule.enabled ? (
                              <BellOff className="h-4 w-4" />
                            ) : (
                              <Bell className="h-4 w-4" />
                            )}
                          </button>
                          <button
                            onClick={() => triggerAlertMutation.mutate(rule.id)}
                            className="p-1 hover:bg-muted rounded"
                            title="Test alert"
                            disabled={triggerAlertMutation.isPending}
                          >
                            <Play className="h-4 w-4" />
                          </button>
                          <button
                            onClick={() => setEditingAlert(rule)}
                            className="p-1 hover:bg-muted rounded"
                            title="Edit alert"
                          >
                            <Edit className="h-4 w-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteAlert(rule.id)}
                            className="p-1 hover:bg-muted rounded text-red-600"
                            title="Delete alert"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </Card>

      {/* Recent Activity */}
      <Card className="p-6">
        <h3 className="text-lg font-medium mb-4">Recent Alert Activity</h3>
        {recentlyTriggered.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <Bell className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p>No recent alert activity</p>
          </div>
        ) : (
          <div className="space-y-3">
            {recentlyTriggered.map((rule) => (
              <div key={rule.id} className="flex items-center justify-between p-3 border border-border rounded-md">
                <div className="flex items-center gap-3">
                  <AlertTriangle className="h-5 w-5 text-yellow-600" />
                  <div>
                    <div className="font-medium">{rule.name}</div>
                    <div className="text-sm text-muted-foreground">
                      {rule.metric_name} {getConditionText(rule.condition)} {rule.threshold}
                    </div>
                  </div>
                </div>
                <div className="text-sm text-muted-foreground">
                  {rule.last_triggered && new Date(rule.last_triggered).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Create Alert Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create Alert Rule"
      >
        <AlertRuleForm
          onSubmit={handleCreateAlert}
          onCancel={() => setShowCreateModal(false)}
          isLoading={createAlertMutation.isPending}
        />
      </Modal>

      {/* Edit Alert Modal */}
      <Modal
        isOpen={!!editingAlert}
        onClose={() => setEditingAlert(null)}
        title="Edit Alert Rule"
      >
        {editingAlert && (
          <AlertRuleForm
            initialData={editingAlert}
            onSubmit={handleUpdateAlert}
            onCancel={() => setEditingAlert(null)}
            isLoading={updateAlertMutation.isPending}
          />
        )}
      </Modal>
    </div>
  )
}