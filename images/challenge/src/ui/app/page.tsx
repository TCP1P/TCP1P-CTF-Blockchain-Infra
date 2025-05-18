"use client"

import { useState, useEffect, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Progress } from "@/components/ui/progress"
import {
  Play,
  CircleStopIcon as Stop,
  Flag,
  Copy,
  Check,
  Terminal,
  Key,
  AlertCircle,
  CheckCircle,
  Cog,
  Send,
  Code,
  CopyCheck,
  X,
  ChevronDown,
  Eye,
  EyeOff,
} from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Toaster } from "@/components/ui/toaster"
import { useToast } from "@/hooks/use-toast"
import { useMobile } from "@/hooks/use-mobile"
import { ThemeToggle } from "@/components/theme-toggle"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"

// Constants for the proof of work challenge
const VERSION = "s"
const MOD = (1n << 1279n) - 1n
const EXP = 1n << 1277n

// Challenge class for proof of work
class Challenge {
  d: number
  x: bigint

  constructor(d: number, x: bigint) {
    this.d = d
    this.x = x
  }

  static fromString(v: string) {
    const [ver, d64, x64] = v.split(".")
    if (ver !== VERSION) throw new Error("Bad version")

    // Read d as 32-bit big-endian integer from base64
    const dBytes = base64ToBytes(d64)
    const d = (dBytes[0] << 24) | (dBytes[1] << 16) | (dBytes[2] << 8) | dBytes[3]

    const x = bytesToBigInt(base64ToBytes(x64))
    return new Challenge(d, x)
  }

  toString() {
    // Create 4-byte buffer for d
    const dBytes = new Uint8Array(4)
    dBytes[0] = (this.d >> 24) & 0xff
    dBytes[1] = (this.d >> 16) & 0xff
    dBytes[2] = (this.d >> 8) & 0xff
    dBytes[3] = this.d & 0xff

    return [VERSION, bytesToBase64(dBytes), bytesToBase64(bigIntToBytes(this.x))].join(".")
  }

  solve() {
    let x = this.x
    for (let i = 0; i < this.d; i++) {
      x = modPow(x, EXP, MOD)
      x = x ^ 1n
    }
    return `${VERSION}.${bytesToBase64(bigIntToBytes(x))}`
  }
}

// Helper functions for crypto operations
function base64ToBytes(b64: string) {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function bytesToBase64(bytes: Uint8Array) {
  const binary = Array.from(bytes)
    .map((byte) => String.fromCharCode(byte))
    .join("")
  return btoa(binary)
}

function bytesToBigInt(bytes: Uint8Array) {
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
  if (hex === "") return 0n
  return BigInt("0x" + hex)
}

function bigIntToBytes(num: bigint) {
  // Number of bytes needed to represent any element of Z/MOD (160 bytes)
  const BYTE_LEN = Math.ceil(1279 / 8)

  let hex = num.toString(16)
  if (hex.length % 2) hex = "0" + hex

  const bytes = new Uint8Array(Math.max(hex.length / 2, BYTE_LEN))

  // Convert hex string to bytes
  const actualLength = hex.length / 2
  for (let i = 0; i < actualLength; i++) {
    bytes[bytes.length - actualLength + i] = Number.parseInt(hex.substr(i * 2, 2), 16)
  }

  return bytes
}

// Helper function for efficient modular exponentiation
function modPow(base: bigint, exponent: bigint, modulus: bigint) {
  let result = 1n
  base = base % modulus
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus
    }
    exponent = exponent >> 1n
    base = (base * base) % modulus
  }
  return result
}

// Types
type Credential = {
  [key: string]: string
}

type Credentials = {
  [key: string]: Credential
  message?: string
  error?: string
}

export default function BlockchainLauncher() {
  // State
  const [isRunning, setIsRunning] = useState(false)
  const [hasCredentials, setHasCredentials] = useState(false)
  const [hasSolution, setHasSolution] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [solution, setSolution] = useState("")
  const [challenge, setChallenge] = useState("")
  const [credentials, setCredentials] = useState<Credentials>({})
  const [solveProgress, setSolveProgress] = useState(0)
  const [isSolving, setIsSolving] = useState(false)
  const [alertType, setAlertType] = useState<"success" | "error" | null>(null)
  const [alertMessage, setAlertMessage] = useState("")
  const [copyState, setCopyState] = useState<{ [key: string]: boolean }>({})
  const [showChallenge, setShowChallenge] = useState(true)
  const [expandedCredentials, setExpandedCredentials] = useState<{ [key: string]: boolean }>({})

  const { toast } = useToast()
  const isMobile = useMobile()
  const alertTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  // Fetch initial data
  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        await Promise.all([getChallenge(), checkStatus()])

        // Load credentials if available
        const response = await fetch("/data")
        const data = await response.json()
        if (Object.keys(data).length > 0 && !data.error) {
          setCredentials(data)
          setHasCredentials(true)
          setIsRunning(true) // Assume running if data loaded
        } else if (data.error) {
          console.warn("Error fetching initial data:", data.error)
        }
      } catch (error) {
        console.error("Error during initialization:", error)
      }
    }

    fetchInitialData()
  }, [])

  // Check if instance is running
  const checkStatus = async () => {
    try {
      const response = await fetch("/status", {
        method: "GET",
        credentials: "include",
      })

      if (!response.ok) {
        let errorMsg = `Status check failed: ${response.status}`
        try {
          const errData = await response.json()
          errorMsg = errData.error || errorMsg
        } catch (e) {
          /* Ignore if response is not JSON */
        }

        console.warn(errorMsg)
        setIsRunning(false)
        return false
      }

      const data = await response.json()
      setIsRunning(data.running)
      return data.running
    } catch (error) {
      console.error("Error checking status:", error)
      setIsRunning(false)
      return false
    }
  }

  // Get challenge
  const getChallenge = async () => {
    try {
      const response = await fetch("/challenge", { method: "GET" })
      if (!response.ok) {
        throw new Error("Failed to get challenge. Server returned: " + response.status)
      }

      const data = await response.json()
      const challengeCmd = `curl -sSfL https://pwn.red/pow | sh -s ${data.challenge}`
      setChallenge(challengeCmd)

      return data.challenge
    } catch (error) {
      showAlert("error", `Error fetching challenge: ${error instanceof Error ? error.message : String(error)}`)
      console.error("Error in getChallenge:", error)
      return null
    }
  }

  // Send solution
  const sendSolution = async () => {
    // Validate solution first
    if (!solution.trim()) {
      showAlert("error", "Solution cannot be empty")
      return
    }

    if (isLoading) return // Prevent double submission

    setIsLoading(true)

    try {
      const response = await fetch("/solution", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ solution }),
      })

      if (!response.ok) {
        let errorData = {}
        try {
          errorData = await response.json()
        } catch (e) {
          /* ignore if not json */
        }

        const errorMessage = (errorData as any)?.error || `Error: ${response.status}`
        throw new Error(errorMessage)
      }

      const data = await response.json()
      showAlert("success", data.message || "Solution accepted!")
      setHasSolution(true)

      toast({
        title: "Success!",
        description: "Solution accepted! You can now launch your instance.",
        duration: 3000,
      })
    } catch (error) {
      showAlert("error", `Error submitting solution: ${error instanceof Error ? error.message : String(error)}`)
      console.error("Error in sendSolution:", error)
    } finally {
      setIsLoading(false)
    }
  }

  // Common function for all actions with proper error handling
  const sendAction = async (action: "launch" | "kill" | "flag", method = "POST") => {
    if (isLoading) return // Prevent multiple simultaneous actions

    setIsLoading(true)

    try {
      const response = await fetch(`/${action}`, {
        method: method,
        credentials: "include",
      })

      let data
      const contentType = response.headers.get("content-type")
      if (contentType && contentType.includes("application/json")) {
        try {
          data = await response.json()
        } catch (e) {
          throw new Error(`Error parsing ${action} response: ${e instanceof Error ? e.message : String(e)}`)
        }
      } else {
        const text = await response.text()
        data = response.ok ? { message: text } : { error: text }
      }

      if (!response.ok) {
        throw new Error(data.error || `Failed to ${action}. Status: ${response.status}`)
      }

      showAlert("success", data.message || `${action} successful`)

      if (action === "launch") {
        if (data && Object.keys(data).length > 0 && !data.error) {
          setCredentials(data)
          setHasCredentials(true)
        }
        setIsRunning(true)

        toast({
          title: "Instance Launched!",
          description: "Your blockchain instance is now running.",
          duration: 3000,
        })

        // Verify status after launch
        setTimeout(() => checkStatus(), 1000)
      } else if (action === "kill") {
        setIsRunning(false)
        toast({
          title: "Instance Terminated!",
          description: "Your blockchain instance has been shut down.",
          duration: 3000,
        })

        // Clear credentials display
        setCredentials({})
        setHasCredentials(false)

        // Verify status after kill
        setTimeout(() => checkStatus(), 1000)
      } else if (action === "flag" && data.flag) {
        displayFlag(data.flag)
      }
    } catch (error) {
      if (error instanceof TypeError && error.message === "Failed to fetch") {
        showAlert("error", "Network error - please check your connection")
      } else {
        showAlert("error", `Error with ${action}: ${error instanceof Error ? error.message : String(error)}`)
      }
      console.error(`Error in ${action}:`, error)
    } finally {
      setIsLoading(false)
    }
  }

  // Launch blockchain instance
  const launchInstance = () => {
    if (!hasSolution && !window.confirm("You haven't submitted a solution. Launch anyway?")) {
      showAlert("error", "Please submit a solution before launching.")
      return
    }
    sendAction("launch", "POST")
  }

  // Terminate blockchain instance
  const killInstance = () => {
    if (!isRunning && !window.confirm("No instance appears to be running. Attempt to terminate anyway?")) {
      showAlert("error", "No instance is currently running to terminate.")
      return
    }
    sendAction("kill", "POST")
  }

  // Get the flag
  const flagInstance = () => {
    if (!isRunning && !window.confirm("No instance appears to be running. Attempt to get flag anyway?")) {
      showAlert("error", "No instance is currently running to get a flag from.")
      return
    }
    sendAction("flag", "GET")
  }

  // Display flag
  const displayFlag = (flag: string) => {
    if (!flag) {
      showAlert("error", "No flag received or flag is empty.")
      return
    }

    toast({
      title: "🚩 Flag Found!",
      description: (
        <div className="mt-2">
          <div className="p-3 bg-background border rounded my-2 font-mono text-sm break-all">{flag}</div>
          <Button
            size="sm"
            className="mt-2 minimal-button"
            onClick={() => {
              navigator.clipboard.writeText(flag)
              toast({
                title: "Copied!",
                description: "Flag copied to clipboard.",
                duration: 2000,
              })
            }}
          >
            <Copy className="mr-2 h-4 w-4" /> Copy Flag
          </Button>
        </div>
      ),
      duration: 10000,
    })
  }

  // Copy challenge command
  const copyChallenge = () => {
    if (!challenge) {
      showAlert("error", "No challenge command to copy.")
      return
    }
    navigator.clipboard
      .writeText(challenge)
      .then(() => {
        setCopyState({ ...copyState, challenge: true })
        setTimeout(() => setCopyState({ ...copyState, challenge: false }), 2000)
      })
      .catch((err) => showAlert("error", "Failed to copy challenge: " + err))
  }

  // Copy credentials in a specific format
  const copyCredentialsAs = (format: "js" | "python" | "rust" | "generic") => {
    if (!credentials || Object.keys(credentials).length === 0) {
      showAlert("error", "No credentials available to copy.")
      return
    }

    const desiredOrder = ["RPC_URL", "PRIVKEY", "SETUP_CONTRACT_ADDR", "WALLET_ADDR"]
    const entries: { entryKey: string; entryValue: string }[] = []

    Object.keys(credentials).forEach((key) => {
      if (key === "message" || key === "error") return

      const obj = credentials[key]
      if (!obj || typeof obj !== "object") return

      const entryKey = Object.keys(obj)[0]
      const entryValue = Object.values(obj)[0]

      if (entryKey === undefined || entryValue === undefined) return

      const formattedValue = entryValue.toString().replace(/\{ORIGIN\}/g, window.location.origin)
      entries.push({ entryKey, entryValue: formattedValue })
    })

    if (entries.length === 0) {
      showAlert("error", "No valid credentials to copy.")
      return
    }

    entries.sort((a, b) => {
      let idxA = desiredOrder.indexOf(a.entryKey)
      let idxB = desiredOrder.indexOf(b.entryKey)
      if (idxA === -1) idxA = Number.POSITIVE_INFINITY // put non-ordered items at the end
      if (idxB === -1) idxB = Number.POSITIVE_INFINITY
      return idxA - idxB
    })

    let credentialsText: string
    let formatName: string

    switch (format) {
      case "js":
        formatName = "JavaScript"
        credentialsText = entries.map((entry) => `const ${entry.entryKey} = "${entry.entryValue}";`).join("\n")
        break
      case "python":
        formatName = "Python"
        credentialsText = entries.map((entry) => `${entry.entryKey} = "${entry.entryValue}"`).join("\n")
        break
      case "rust":
        formatName = "Rust"
        credentialsText = entries.map((entry) => `let ${entry.entryKey}: &str = "${entry.entryValue}";`).join("\n")
        break
      default:
        formatName = "generic"
        credentialsText = entries.map((entry) => `${entry.entryKey} = "${entry.entryValue}"`).join("\n")
    }

    navigator.clipboard
      .writeText(credentialsText)
      .then(() => {
        showAlert("success", `Credentials copied as ${formatName} format!`)
        setCopyState({ ...copyState, credentials: true })
        setTimeout(() => setCopyState({ ...copyState, credentials: false }), 2000)
      })
      .catch((err) => showAlert("error", "Failed to copy credentials: " + err))
  }

  // Extract challenge string from the displayed command
  const extractChallengeString = () => {
    if (!challenge) {
      showAlert("error", "No challenge to solve.")
      return null
    }

    // Extract the challenge string from the command
    const match = challenge.match(/curl -sSfL https:\/\/pwn\.red\/pow \| sh -s (s\.[^.]+\.[^.]+)/)
    if (!match || !match[1]) {
      showAlert("error", "Could not extract challenge from command.")
      return null
    }

    return match[1]
  }

  // Parse challenge string into Challenge object
  const parseChallenge = (challengeStr: string) => {
    try {
      return Challenge.fromString(challengeStr)
    } catch (error) {
      showAlert("error", `Error parsing challenge: ${error instanceof Error ? error.message : String(error)}`)
      console.error("Parse error details:", error)
      return null
    }
  }

  // Solve the challenge using the Challenge class
  const solvePowChallenge = async (challenge: Challenge) => {
    // Initial progress
    setSolveProgress(5)
    await new Promise((resolve) => setTimeout(resolve, 50))

    try {
      // Split the work into chunks to avoid freezing the UI
      let solution = null

      // Use incremental progress updates
      const progressSteps = Math.min(50, challenge.d) // More granular updates
      const progressIncrement = 90 / progressSteps // 5% to 95%

      let completedSteps = 0
      const updateProgress = () => {
        completedSteps++
        const progress = 5 + completedSteps * progressIncrement
        setSolveProgress(progress)
      }

      // Process in batches to keep UI responsive
      solution = await new Promise<string>((resolve) => {
        let x = challenge.x

        // Process iterations in batches
        let i = 0
        function processBatch() {
          const startTime = Date.now()
          const batchSize = Math.max(1, Math.floor(challenge.d / progressSteps))

          while (i < challenge.d) {
            x = modPow(x, EXP, MOD)
            x = x ^ 1n
            i++

            // Update progress more frequently
            if (i % batchSize === 0) {
              updateProgress()
            }

            // Break batch after 16ms (roughly one frame) to keep UI responsive
            if (Date.now() - startTime > 16) {
              setTimeout(processBatch, 0)
              return
            }
          }

          // Complete
          const solution = `${VERSION}.${bytesToBase64(bigIntToBytes(x))}`
          resolve(solution)
        }

        setTimeout(processBatch, 0)
      })

      // Final progress update
      setSolveProgress(100)
      await new Promise((resolve) => setTimeout(resolve, 100))

      return solution
    } catch (error) {
      console.error("Error in POW calculation:", error)
      throw new Error(`Failed to calculate proof-of-work: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  // UI function to solve the challenge
  const solveChallenge = async () => {
    // Check for BigInt support
    if (typeof BigInt !== "function") {
      showAlert("error", "Your browser doesn't support BigInt. Please use a modern browser.")
      return
    }

    if (isLoading || isSolving) return // Prevent running if already processing something

    // Extract and parse the challenge
    const challengeStr = extractChallengeString()
    if (!challengeStr) return

    const challengeObj = parseChallenge(challengeStr)
    if (!challengeObj) return

    // Show progress and disable button
    setIsSolving(true)
    setSolveProgress(0)

    try {
      // Clear any previous solution
      setSolution("")

      // Solve the challenge
      const solutionResult = await solvePowChallenge(challengeObj)

      // Set the solution in the input field
      setSolution(solutionResult)

      // Complete progress
      setSolveProgress(100)

      // Show success message
      showAlert("success", "Solution found! Click Submit to continue.")

      toast({
        title: "Solution Found!",
        description: "Click Submit to continue.",
        duration: 3000,
      })
    } catch (error) {
      showAlert("error", `Error solving challenge: ${error instanceof Error ? error.message : String(error)}`)
      console.error("Solver error:", error)
    } finally {
      // Reset progress bar after a short delay
      setTimeout(() => {
        setIsSolving(false)
        setSolveProgress(0)
      }, 1000)
    }
  }

  // Show alert message
  const showAlert = (type: "success" | "error", message: string) => {
    setAlertType(type)
    setAlertMessage(message)

    // Clear any existing timeout
    if (alertTimeoutRef.current) {
      clearTimeout(alertTimeoutRef.current)
    }

    // Set a new timeout to clear the alert
    alertTimeoutRef.current = setTimeout(() => {
      setAlertType(null)
      setAlertMessage("")
    }, 5000)
  }

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (alertTimeoutRef.current) {
        clearTimeout(alertTimeoutRef.current)
      }
    }
  }, [])

  // Toggle credential expansion
  const toggleCredentialExpansion = (key: string) => {
    setExpandedCredentials({
      ...expandedCredentials,
      [key]: !expandedCredentials[key],
    })
  }

  // Truncate text with ellipsis
  const truncateText = (text: string, maxLength: number) => {
    if (text.length <= maxLength) return text
    return text.substring(0, maxLength) + "..."
  }

  // Render credentials table
  const renderCredentialsTable = () => {
    if (!credentials || Object.keys(credentials).length === 0) {
      return (
        <div className="text-center py-12 text-muted-foreground flex flex-col items-center justify-center">
          <div className="rounded-full bg-muted p-3 mb-4">
            <Key className="h-6 w-6 text-muted-foreground/60" />
          </div>
          <p>No credentials to display.</p>
          <p className="text-sm mt-2">Launch an instance to see credentials here.</p>
        </div>
      )
    }

    const credentialEntries: { key: string; name: string; value: string }[] = []

    Object.keys(credentials).forEach((key) => {
      if (key === "message" || key === "error") return

      const obj = credentials[key]
      if (!obj || typeof obj !== "object") return

      const entryKey = Object.keys(obj)[0]
      const entryValue = Object.values(obj)[0]

      if (entryKey === undefined || entryValue === undefined) return

      const formattedValue = entryValue.toString().replace(/\{ORIGIN\}/g, window.location.origin)
      credentialEntries.push({ key, name: entryKey, value: formattedValue })
    })

    if (credentialEntries.length === 0) {
      return (
        <div className="text-center py-12 text-muted-foreground flex flex-col items-center justify-center">
          <div className="rounded-full bg-muted p-3 mb-4">
            <Key className="h-6 w-6 text-muted-foreground/60" />
          </div>
          <p>No credentials to display.</p>
          <p className="text-sm mt-2">Launch an instance to see credentials here.</p>
        </div>
      )
    }

    return (
      <div className="space-y-4">
        {credentialEntries.map((entry) => (
          <div key={entry.key} className="bg-muted/30 rounded-lg p-3 hover:bg-muted/50 transition-colors duration-200">
            <div className="flex justify-between items-center mb-1">
              <div className="font-medium text-primary">{entry.name}</div>
              <div className="flex space-x-1">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => toggleCredentialExpansion(entry.key)}
                      >
                        {expandedCredentials[entry.key] ? (
                          <EyeOff className="h-3.5 w-3.5 text-muted-foreground" />
                        ) : (
                          <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                        )}
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent side="top">{expandedCredentials[entry.key] ? "Collapse" : "Expand"}</TooltipContent>
                  </Tooltip>
                </TooltipProvider>

                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => {
                          navigator.clipboard.writeText(entry.value)
                          toast({
                            title: "Copied!",
                            description: `${entry.name} copied to clipboard.`,
                            duration: 2000,
                          })
                        }}
                      >
                        <Copy className="h-3.5 w-3.5 text-muted-foreground" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent side="top">Copy to clipboard</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </div>
            </div>
            <div className="font-mono text-xs bg-background/50 p-2 rounded border border-border/50">
              {expandedCredentials[entry.key] ? (
                <div className="break-all">{entry.value}</div>
              ) : (
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <div className="truncate cursor-help">{truncateText(entry.value, 40)}</div>
                    </TooltipTrigger>
                    <TooltipContent side="bottom" className="max-w-sm">
                      <p className="break-all font-mono text-xs">{entry.value}</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              )}
            </div>
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-5xl">
      <div className="flex justify-between items-center mb-8 fade-in">
        <h1 className="text-2xl font-medium">Blockchain Launcher</h1>
        <ThemeToggle />
      </div>

      {/* Status Bar */}
      <div className="mb-6 p-3 bg-background border rounded-lg flex items-center justify-between fade-in">
        <div className="flex items-center">
          <span className={`status-indicator ${isRunning ? "status-active" : "status-inactive"}`}></span>
          <span className="text-sm font-medium">{isRunning ? "Instance Running" : "No Instance Running"}</span>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline" size="sm" className="minimal-button" onClick={launchInstance} disabled={isLoading}>
            <Play className="h-4 w-4 mr-1" /> Launch
          </Button>
          <Button variant="outline" size="sm" className="minimal-button" onClick={killInstance} disabled={isLoading}>
            <Stop className="h-4 w-4 mr-1" /> Stop
          </Button>
          <Button variant="outline" size="sm" className="minimal-button" onClick={flagInstance} disabled={isLoading}>
            <Flag className="h-4 w-4 mr-1" /> Flag
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column */}
        <div className="flex flex-col space-y-6 h-[500px]">
          {/* Solution Form */}
          <Card className="minimal-card border shadow-sm flex-1">
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <Terminal className="mr-2 h-5 w-5" /> Solution
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="relative">
                    <Input
                      value={solution}
                      onChange={(e) => setSolution(e.target.value)}
                      placeholder="Enter your solution here"
                      className="font-mono pr-10 minimal-input"
                    />
                    {solution && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute right-1 top-1/2 transform -translate-y-1/2 h-7 w-7"
                        onClick={() => setSolution("")}
                      >
                        <X className="h-4 w-4 text-muted-foreground hover:text-foreground transition-colors" />
                      </Button>
                    )}
                  </div>
                </div>

                <Button onClick={sendSolution} disabled={isLoading} className="w-full minimal-button">
                  {isLoading ? (
                    <span className="flex items-center">
                      <svg
                        className="animate-spin -ml-1 mr-2 h-4 w-4"
                        xmlns="http://www.w3.org/2000/svg"
                        fill="none"
                        viewBox="0 0 24 24"
                      >
                        <circle
                          className="opacity-25"
                          cx="12"
                          cy="12"
                          r="10"
                          stroke="currentColor"
                          strokeWidth="4"
                        ></circle>
                        <path
                          className="opacity-75"
                          fill="currentColor"
                          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                        ></path>
                      </svg>
                      Processing...
                    </span>
                  ) : (
                    <span className="flex items-center">
                      <Send className="mr-2 h-4 w-4" /> Submit Solution
                    </span>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Challenge Section */}
          <Card className="minimal-card border shadow-sm flex-1">
            <CardHeader className="pb-2">
              <div className="flex justify-between items-center">
                <CardTitle className="text-lg flex items-center">
                  <Code className="mr-2 h-5 w-5" /> Challenge
                </CardTitle>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 w-8 p-0"
                  onClick={() => setShowChallenge(!showChallenge)}
                >
                  <ChevronDown
                    className={`h-4 w-4 transition-transform duration-200 ${showChallenge ? "rotate-180" : ""}`}
                  />
                </Button>
              </div>
            </CardHeader>
            {showChallenge && (
              <CardContent className="space-y-4">
                <div className="relative group">
                  <div className="bg-muted p-3 rounded-md font-mono text-sm overflow-x-auto custom-scrollbar-x terminal-text">
                    {challenge}
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                    onClick={copyChallenge}
                  >
                    {copyState.challenge ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                  </Button>
                </div>

                <div className="space-y-2">
                  <Button className="w-full minimal-button" onClick={solveChallenge} disabled={isSolving}>
                    {isSolving ? (
                      <span className="flex items-center">
                        <svg
                          className="animate-spin -ml-1 mr-2 h-4 w-4"
                          xmlns="http://www.w3.org/2000/svg"
                          fill="none"
                          viewBox="0 0 24 24"
                        >
                          <circle
                            className="opacity-25"
                            cx="12"
                            cy="12"
                            r="10"
                            stroke="currentColor"
                            strokeWidth="4"
                          ></circle>
                          <path
                            className="opacity-75"
                            fill="currentColor"
                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                          ></path>
                        </svg>
                        Solving...
                      </span>
                    ) : (
                      <span className="flex items-center">
                        <Cog className="mr-2 h-4 w-4" /> Solve in Browser
                      </span>
                    )}
                  </Button>

                  {isSolving && (
                    <div className="space-y-1">
                      <Progress
                        value={solveProgress}
                        className="h-1.5"
                        indicatorClassName="bg-primary progress-bar-animated"
                      />
                      <p className="text-xs text-center text-muted-foreground">
                        {solveProgress < 100 ? `Processing: ${Math.round(solveProgress)}%` : "Complete!"}
                      </p>
                    </div>
                  )}
                </div>
              </CardContent>
            )}
          </Card>

          {/* Alert Messages */}
          {alertType && (
            <Alert variant={alertType === "error" ? "destructive" : "default"} className="slide-up">
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  {alertType === "error" ? (
                    <AlertCircle className="h-4 w-4 mr-2" />
                  ) : (
                    <CheckCircle className="h-4 w-4 mr-2" />
                  )}
                  <AlertDescription>{alertMessage}</AlertDescription>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 -mr-2"
                  onClick={() => {
                    setAlertType(null)
                    setAlertMessage("")
                  }}
                >
                  <X className="h-3 w-3" />
                </Button>
              </div>
            </Alert>
          )}
        </div>

        {/* Right Column - Credentials */}
        <div className="h-[500px]">
          <Card className="h-full minimal-card border shadow-sm">
            <CardHeader className="pb-2">
              <div className="flex justify-between items-center">
                <CardTitle className="text-lg flex items-center">
                  <Key className="mr-2 h-5 w-5" /> Credentials
                </CardTitle>

                {hasCredentials && (
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm" className="minimal-button">
                        {copyState.credentials ? (
                          <CopyCheck className="mr-2 h-4 w-4" />
                        ) : (
                          <Copy className="mr-2 h-4 w-4" />
                        )}
                        Copy as
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="slide-up">
                      <DropdownMenuItem onClick={() => copyCredentialsAs("js")} className="cursor-pointer">
                        <span className="mr-2 text-yellow-500">JS</span> JavaScript
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => copyCredentialsAs("python")} className="cursor-pointer">
                        <span className="mr-2 text-blue-500">PY</span> Python
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => copyCredentialsAs("rust")} className="cursor-pointer">
                        <span className="mr-2 text-orange-500">RS</span> Rust
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                )}
              </div>
            </CardHeader>
            <CardContent className="h-[calc(100%-60px)] overflow-y-auto thin-scrollbar">
              {renderCredentialsTable()}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Footer */}
      <footer className="mt-8 pt-4 border-t text-center text-sm text-muted-foreground">
        <p className="flex items-center justify-center">
          <svg viewBox="0 0 24 24" className="h-4 w-4 mr-2 text-primary" fill="currentColor">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
          </svg>
          <a
            href="https://github.com/TCP1P/TCP1P-CTF-Blockchain-Infra"
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary hover:underline ml-1 transition-colors duration-200"
          >
            TCP1P-CTF-Blockchain-Infra
          </a>
        </p>
      </footer>

      <Toaster />
    </div>
  )
}
