import { Link } from 'react-router-dom'
import { ArrowLeft, Construction, Bell, Users } from 'lucide-react'

interface ComingSoonProps {
  title: string
  description: string
}

export function ComingSoon({ title, description }: ComingSoonProps) {
  return (
    <div className="min-h-[80vh] flex items-center justify-center p-8 animate-fade-in">
      <div className="max-w-md text-center">
        <div className="w-20 h-20 mx-auto mb-6 bg-gradient-to-br from-blue-500/20 to-purple-500/20 rounded-2xl flex items-center justify-center">
          <Construction className="w-10 h-10 text-blue-400" />
        </div>
        <h1 className="text-3xl font-bold text-white mb-3">{title}</h1>
        <p className="text-slate-400 mb-8">{description}</p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
          <Link to="/" className="btn-secondary">
            <ArrowLeft className="w-4 h-4" />
            Back to Dashboard
          </Link>
          <a
            href="mailto:support@omniguard.io?subject=Feature Request: ${title}"
            className="btn-primary"
          >
            <Bell className="w-4 h-4" />
            Request Early Access
          </a>
        </div>
        <p className="text-xs text-slate-600 mt-6">
          This feature is coming soon. Want to help shape it?{' '}
          <a href="https://github.com/omniguard/omniguard/discussions" className="text-blue-400 hover:text-blue-300">
            Join the discussion
          </a>
        </p>
      </div>
    </div>
  )
}
