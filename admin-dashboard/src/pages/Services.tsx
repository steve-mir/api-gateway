import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Plus, 
  Search, 
  Filter, 
  MoreHorizontal, 
  Edit, 
  Trash2, 
  Activity,
  Server,
  CheckCircle,
  XCircle,
  AlertTriangle
} from 'lucide-react'
import toast from 'react-hot-toast'
import { adminApi } from '@/lib/api'
import { ServiceInstance, ServiceStatus } from '@/types'
import { getStatusColor } from '@/lib/utils'
import { Card } from '@/components/ui/Card'
import { ServiceForm } from '@/components/forms/ServiceForm'
import { Modal } from '@/components/ui/Modal'
import { Button } from '@/components/ui/Button'

export function Services() {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingService, setEditingService] = useState<ServiceInstance | null>(null)
  const [selectedServices, setSelectedServices] = useState<string[]>([])

  const queryClient = useQueryClient()

  const { data: servicesData, isLoading } = useQuery({
    queryKey: ['services', statusFilter],
    queryFn: () => adminApi.getServices(
      statusFilter !== 'all' ? { health_status: statusFilter } : undefined
    ),
    refetchInterval: 30000,
  })

  const createServiceMutation = useMutation({
    mutationFn: adminApi.createService,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['services'] })
      setShowCreateModal(false)
      toast.success('Service created successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to create service')
    },
  })

  const updateServiceMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => 
      adminApi.updateService(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['services'] })
      setEditingService(null)
      toast.success('Service updated successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to update service')
    },
  })

  const deleteServiceMutation = useMutation({
    mutationFn: (serviceId: string) => adminApi.deleteService(serviceId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['services'] })
      toast.success('Service deleted successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to delete service')
    },
  })

  const services = servicesData?.data?.services || []
  const allInstances = services.flatMap(service => service.instances)

  const filteredInstances = allInstances.filter(instance => {
    const matchesSearch = instance.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         instance.address.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesSearch
  })

  const getStatusIcon = (status?: ServiceStatus) => {
    switch (status) {
      case ServiceStatus.Healthy:
        return <CheckCircle className="h-4 w-4 text-green-600" />
      case ServiceStatus.Unhealthy:
        return <XCircle className="h-4 w-4 text-red-600" />
      case ServiceStatus.Warning:
        return <AlertTriangle className="h-4 w-4 text-yellow-600" />
      default:
        return <Activity className="h-4 w-4 text-gray-600" />
    }
  }

  const handleCreateService = (data: any) => {
    createServiceMutation.mutate(data)
  }

  const handleUpdateService = (data: any) => {
    if (editingService) {
      updateServiceMutation.mutate({ id: editingService.id, data })
    }
  }

  const handleDeleteService = (serviceId: string) => {
    if (confirm('Are you sure you want to delete this service?')) {
      deleteServiceMutation.mutate(serviceId)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Services</h1>
          <p className="text-muted-foreground">
            Manage service instances and their health status
          </p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Add Service
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4">
          <div className="flex items-center">
            <Server className="h-8 w-8 text-blue-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Total Services</p>
              <p className="text-2xl font-bold">{servicesData?.data?.total_services || 0}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center">
            <CheckCircle className="h-8 w-8 text-green-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Healthy</p>
              <p className="text-2xl font-bold">
                {services.reduce((acc, service) => acc + service.healthy_instances, 0)}
              </p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center">
            <XCircle className="h-8 w-8 text-red-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Unhealthy</p>
              <p className="text-2xl font-bold">
                {services.reduce((acc, service) => acc + (service.instance_count - service.healthy_instances), 0)}
              </p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center">
            <Activity className="h-8 w-8 text-purple-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Total Instances</p>
              <p className="text-2xl font-bold">{servicesData?.data?.total_instances || 0}</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Filters and Search */}
      <Card className="p-4">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search services..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="all">All Status</option>
              <option value="healthy">Healthy</option>
              <option value="unhealthy">Unhealthy</option>
              <option value="warning">Warning</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Services Table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">
                  <input
                    type="checkbox"
                    className="rounded border-input"
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedServices(filteredInstances.map(i => i.id))
                      } else {
                        setSelectedServices([])
                      }
                    }}
                  />
                </th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Status</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Name</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Address</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Protocol</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Weight</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="text-center py-8">
                    <div className="spinner w-6 h-6 mx-auto"></div>
                  </td>
                </tr>
              ) : filteredInstances.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-muted-foreground">
                    No services found
                  </td>
                </tr>
              ) : (
                filteredInstances.map((instance) => (
                  <tr key={instance.id} className="border-b border-border hover:bg-muted/50">
                    <td className="py-3 px-4">
                      <input
                        type="checkbox"
                        className="rounded border-input"
                        checked={selectedServices.includes(instance.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedServices([...selectedServices, instance.id])
                          } else {
                            setSelectedServices(selectedServices.filter(id => id !== instance.id))
                          }
                        }}
                      />
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(instance.health_status)}
                        <span className={`px-2 py-1 text-xs font-medium rounded-full border ${
                          getStatusColor(instance.health_status || 'unknown')
                        }`}>
                          {instance.health_status || 'Unknown'}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4 font-medium">{instance.name}</td>
                    <td className="py-3 px-4 font-mono text-sm">{instance.address}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-1 text-xs font-medium bg-secondary text-secondary-foreground rounded">
                        {instance.protocol.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4">{instance.weight}</td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setEditingService(instance)}
                          className="p-1 hover:bg-muted rounded"
                          title="Edit service"
                        >
                          <Edit className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteService(instance.id)}
                          className="p-1 hover:bg-muted rounded text-red-600"
                          title="Delete service"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                        <button className="p-1 hover:bg-muted rounded">
                          <MoreHorizontal className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Create Service Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Add New Service"
      >
        <ServiceForm
          onSubmit={handleCreateService}
          onCancel={() => setShowCreateModal(false)}
          isLoading={createServiceMutation.isPending}
        />
      </Modal>

      {/* Edit Service Modal */}
      <Modal
        isOpen={!!editingService}
        onClose={() => setEditingService(null)}
        title="Edit Service"
      >
        {editingService && (
          <ServiceForm
            initialData={editingService}
            onSubmit={handleUpdateService}
            onCancel={() => setEditingService(null)}
            isLoading={updateServiceMutation.isPending}
          />
        )}
      </Modal>
    </div>
  )
}