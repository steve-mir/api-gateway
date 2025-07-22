import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Network } from 'vis-network'
import { DataSet } from 'vis-data'
import { 
  RefreshCw, 
  ZoomIn, 
  ZoomOut, 
  Maximize2, 
  Settings,
  Filter,
  Download
} from 'lucide-react'
import { adminApi } from '@/lib/api'
import { ServiceInstance, NetworkNode, NetworkEdge, TopologyData } from '@/types'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'

export function ServiceTopology() {
  const networkRef = useRef<HTMLDivElement>(null)
  const networkInstance = useRef<Network | null>(null)
  const [selectedNode, setSelectedNode] = useState<string | null>(null)
  const [layoutType, setLayoutType] = useState<'hierarchical' | 'physics'>('hierarchical')
  const [showLabels, setShowLabels] = useState(true)
  const [filterProtocol, setFilterProtocol] = useState<string>('all')

  const { data: servicesData, refetch } = useQuery({
    queryKey: ['services-topology'],
    queryFn: () => adminApi.getServices(),
    refetchInterval: 30000,
  })

  const { data: healthData } = useQuery({
    queryKey: ['services-health'],
    queryFn: () => adminApi.getAllServicesHealth(),
    refetchInterval: 15000,
  })

  // Transform services data into network topology
  const generateTopologyData = (): TopologyData => {
    const services = servicesData?.data?.services || []
    const nodes: NetworkNode[] = []
    const edges: NetworkEdge[] = []

    // Add gateway node
    nodes.push({
      id: 'gateway',
      label: 'API Gateway',
      group: 'gateway',
      level: 0,
      color: '#3b82f6',
      shape: 'box',
      size: 30,
      font: { size: 16, color: '#ffffff' }
    })

    // Add service nodes
    services.forEach((service, serviceIndex) => {
      service.instances.forEach((instance, instanceIndex) => {
        const healthStatus = healthData?.data?.services?.[instance.id] || 'Unknown'
        const nodeColor = getNodeColor(healthStatus)
        
        // Filter by protocol if specified
        if (filterProtocol !== 'all' && instance.protocol !== filterProtocol) {
          return
        }

        nodes.push({
          id: instance.id,
          label: showLabels ? `${instance.name}\n${instance.address}` : instance.name,
          group: instance.protocol,
          level: 1,
          color: nodeColor,
          shape: getNodeShape(instance.protocol),
          size: 20,
          font: { size: 12 }
        })

        // Add edge from gateway to service
        edges.push({
          id: `gateway-${instance.id}`,
          from: 'gateway',
          to: instance.id,
          label: instance.protocol.toUpperCase(),
          arrows: 'to',
          color: '#94a3b8',
          width: 2
        })
      })
    })

    // Add connections between services (mock data for demonstration)
    // In a real implementation, this would come from service mesh or tracing data
    if (nodes.length > 2) {
      const serviceNodes = nodes.filter(n => n.id !== 'gateway')
      for (let i = 0; i < Math.min(serviceNodes.length - 1, 3); i++) {
        edges.push({
          id: `service-${i}-${i + 1}`,
          from: serviceNodes[i].id,
          to: serviceNodes[i + 1].id,
          label: 'calls',
          arrows: 'to',
          color: '#e2e8f0',
          width: 1
        })
      }
    }

    return { nodes, edges }
  }

  const getNodeColor = (healthStatus: string) => {
    switch (healthStatus.toLowerCase()) {
      case 'healthy':
        return '#10b981'
      case 'unhealthy':
        return '#ef4444'
      case 'warning':
        return '#f59e0b'
      default:
        return '#6b7280'
    }
  }

  const getNodeShape = (protocol: string) => {
    switch (protocol) {
      case 'grpc':
        return 'diamond'
      case 'websocket':
        return 'triangle'
      default:
        return 'dot'
    }
  }

  // Initialize network
  useEffect(() => {
    if (!networkRef.current || !servicesData) return

    const topologyData = generateTopologyData()
    const nodes = new DataSet(topologyData.nodes)
    const edges = new DataSet(topologyData.edges)

    const options = {
      layout: {
        hierarchical: layoutType === 'hierarchical' ? {
          enabled: true,
          direction: 'UD',
          sortMethod: 'directed',
          levelSeparation: 150,
          nodeSpacing: 200,
        } : false,
      },
      physics: {
        enabled: layoutType === 'physics',
        stabilization: { iterations: 100 },
        barnesHut: {
          gravitationalConstant: -2000,
          centralGravity: 0.3,
          springLength: 95,
          springConstant: 0.04,
          damping: 0.09,
        },
      },
      nodes: {
        borderWidth: 2,
        shadow: true,
        font: {
          color: '#374151',
          size: 12,
        },
      },
      edges: {
        shadow: true,
        smooth: {
          type: 'continuous',
        },
      },
      interaction: {
        hover: true,
        selectConnectedEdges: false,
      },
    }

    networkInstance.current = new Network(
      networkRef.current,
      { nodes, edges },
      options
    )

    // Handle node selection
    networkInstance.current.on('selectNode', (params) => {
      if (params.nodes.length > 0) {
        setSelectedNode(params.nodes[0])
      }
    })

    networkInstance.current.on('deselectNode', () => {
      setSelectedNode(null)
    })

    return () => {
      if (networkInstance.current) {
        networkInstance.current.destroy()
        networkInstance.current = null
      }
    }
  }, [servicesData, healthData, layoutType, showLabels, filterProtocol])

  const handleZoomIn = () => {
    if (networkInstance.current) {
      const scale = networkInstance.current.getScale()
      networkInstance.current.moveTo({ scale: scale * 1.2 })
    }
  }

  const handleZoomOut = () => {
    if (networkInstance.current) {
      const scale = networkInstance.current.getScale()
      networkInstance.current.moveTo({ scale: scale * 0.8 })
    }
  }

  const handleFit = () => {
    if (networkInstance.current) {
      networkInstance.current.fit()
    }
  }

  const handleExport = () => {
    if (networkInstance.current) {
      const canvas = networkInstance.current.canvas.frame.canvas
      const link = document.createElement('a')
      link.download = 'service-topology.png'
      link.href = canvas.toDataURL()
      link.click()
    }
  }

  const selectedService = selectedNode && servicesData?.data?.services
    ?.flatMap(s => s.instances)
    ?.find(i => i.id === selectedNode)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Service Topology</h1>
          <p className="text-muted-foreground">
            Visualize service relationships and health status
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={handleExport}>
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Controls Panel */}
        <Card className="p-4 lg:col-span-1">
          <h3 className="font-medium mb-4">Controls</h3>
          
          <div className="space-y-4">
            {/* Layout Type */}
            <div>
              <label className="block text-sm font-medium mb-2">Layout</label>
              <select
                value={layoutType}
                onChange={(e) => setLayoutType(e.target.value as any)}
                className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="hierarchical">Hierarchical</option>
                <option value="physics">Physics</option>
              </select>
            </div>

            {/* Protocol Filter */}
            <div>
              <label className="block text-sm font-medium mb-2">Protocol</label>
              <select
                value={filterProtocol}
                onChange={(e) => setFilterProtocol(e.target.value)}
                className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="all">All Protocols</option>
                <option value="http">HTTP</option>
                <option value="grpc">gRPC</option>
                <option value="websocket">WebSocket</option>
              </select>
            </div>

            {/* Show Labels */}
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="showLabels"
                checked={showLabels}
                onChange={(e) => setShowLabels(e.target.checked)}
                className="rounded border-input"
              />
              <label htmlFor="showLabels" className="text-sm font-medium">
                Show Labels
              </label>
            </div>

            {/* Zoom Controls */}
            <div className="space-y-2">
              <label className="block text-sm font-medium">Zoom</label>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={handleZoomIn}>
                  <ZoomIn className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="sm" onClick={handleZoomOut}>
                  <ZoomOut className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="sm" onClick={handleFit}>
                  <Maximize2 className="h-4 w-4" />
                </Button>
              </div>
            </div>

            {/* Legend */}
            <div>
              <label className="block text-sm font-medium mb-2">Legend</label>
              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-blue-500 rounded"></div>
                  <span>Gateway</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                  <span>Healthy Service</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                  <span>Unhealthy Service</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                  <span>Warning Service</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-gray-500 rounded-full"></div>
                  <span>Unknown Status</span>
                </div>
              </div>
            </div>
          </div>
        </Card>

        {/* Network Visualization */}
        <Card className="p-4 lg:col-span-3">
          <div className="relative">
            <div
              ref={networkRef}
              className="w-full h-96 border border-border rounded-md bg-background"
            />
            
            {/* Selected Node Info */}
            {selectedService && (
              <div className="absolute top-4 right-4 bg-card border border-border rounded-md p-4 shadow-lg max-w-xs">
                <h4 className="font-medium mb-2">{selectedService.name}</h4>
                <div className="space-y-1 text-sm">
                  <div><strong>Address:</strong> {selectedService.address}</div>
                  <div><strong>Protocol:</strong> {selectedService.protocol.toUpperCase()}</div>
                  <div><strong>Weight:</strong> {selectedService.weight}</div>
                  <div>
                    <strong>Status:</strong>{' '}
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      selectedService.health_status === 'Healthy' ? 'bg-green-100 text-green-800' :
                      selectedService.health_status === 'Unhealthy' ? 'bg-red-100 text-red-800' :
                      selectedService.health_status === 'Warning' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {selectedService.health_status || 'Unknown'}
                    </span>
                  </div>
                  {Object.keys(selectedService.metadata || {}).length > 0 && (
                    <div>
                      <strong>Metadata:</strong>
                      <div className="mt-1 space-y-1">
                        {Object.entries(selectedService.metadata || {}).map(([key, value]) => (
                          <div key={key} className="text-xs">
                            <span className="font-mono">{key}:</span> {value}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-foreground">
              {servicesData?.data?.total_services || 0}
            </div>
            <div className="text-sm text-muted-foreground">Total Services</div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">
              {servicesData?.data?.services?.reduce((acc, service) => acc + service.healthy_instances, 0) || 0}
            </div>
            <div className="text-sm text-muted-foreground">Healthy Instances</div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-red-600">
              {servicesData?.data?.services?.reduce((acc, service) => acc + (service.instance_count - service.healthy_instances), 0) || 0}
            </div>
            <div className="text-sm text-muted-foreground">Unhealthy Instances</div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-foreground">
              {servicesData?.data?.total_instances || 0}
            </div>
            <div className="text-sm text-muted-foreground">Total Instances</div>
          </div>
        </Card>
      </div>
    </div>
  )
}