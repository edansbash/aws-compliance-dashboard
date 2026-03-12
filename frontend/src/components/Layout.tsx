import { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  AlertTriangle,
  Scan,
  BookOpen,
  ShieldOff,
  Building2,
  ClipboardList,
  Wrench,
  Package,
  Settings,
  FileText,
} from 'lucide-react'
import { clsx } from 'clsx'

interface LayoutProps {
  children: ReactNode
}

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Findings', href: '/findings', icon: AlertTriangle },
  { name: 'Scans', href: '/scans', icon: Scan },
  { name: 'Rules', href: '/rules', icon: BookOpen },
  { name: 'Compliance Packs', href: '/compliance-packs', icon: Package },
  { name: 'Exceptions', href: '/exceptions', icon: ShieldOff },
  { name: 'Remediation', href: '/remediation', icon: Wrench },
  { name: 'Audit Logs', href: '/audit-logs', icon: ClipboardList },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Accounts', href: '/accounts', icon: Building2 },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <div className="w-64 bg-gray-900 text-white flex flex-col">
        <div className="p-4 border-b border-gray-800">
          <h1 className="text-xl font-bold">AWS Compliance</h1>
          <p className="text-gray-400 text-sm">Dashboard</p>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href
            return (
              <Link
                key={item.name}
                to={item.href}
                className={clsx(
                  'flex items-center gap-3 px-3 py-2 rounded-lg transition-colors',
                  isActive
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                )}
              >
                <item.icon className="w-5 h-5" />
                {item.name}
              </Link>
            )
          })}
        </nav>

        <div className="p-4 border-t border-gray-800 text-gray-400 text-sm">
          v1.0.0
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col">
        <main className="flex-1 p-6 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  )
}
