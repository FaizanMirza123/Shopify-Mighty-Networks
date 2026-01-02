import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import {
  Send,
  X,
  Check,
  Users,
  CreditCard,
  LogOut,
  Loader2,
} from "lucide-react";
import useEmblaCarousel from "embla-carousel-react";
import * as Dialog from "@radix-ui/react-dialog";
import { useForm } from "react-hook-form";
import { useNavigate } from "react-router-dom";
import { cn } from "../lib/utils";
import { api } from "../services/api";

const COLORS = ["#fcc554", "#e5e7eb"]; // Primary and Gray

const Dashboard = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [plans, setPlans] = useState([]);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [invites, setInvites] = useState([]);
  const [emblaRef] = useEmblaCarousel({ loop: false, align: "start" });
  const { register, handleSubmit, reset } = useForm();
  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [inviteError, setInviteError] = useState("");
  const [isInviting, setIsInviting] = useState(false);

  useEffect(() => {
    // Get user from localStorage
    const userData = localStorage.getItem("user");
    if (!userData) {
      navigate("/login");
      return;
    }

    const parsedUser = JSON.parse(userData);
    setUser(parsedUser);

    // Fetch user plans and invites
    fetchData(parsedUser.id);
  }, [navigate]);

  const fetchData = async (userId) => {
    setIsLoading(true);
    try {
      const [plansResponse, invitesResponse] = await Promise.all([
        api.getUserPlans(userId),
        api.getUserInvites(userId),
      ]);

      setPlans(plansResponse.plans);
      setInvites(invitesResponse.invites);

      if (plansResponse.plans.length > 0) {
        setSelectedPlan(plansResponse.plans[0]);
      }
    } catch (err) {
      setError(err.message || "Failed to load data");
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("user");
    localStorage.removeItem("access_token");
    navigate("/login");
  };

  const handleInvite = async (data) => {
    if (!selectedPlan) return;

    setInviteError("");
    setIsInviting(true);

    try {
      const response = await api.sendInvite(
        user.id,
        selectedPlan.id,
        data.email,
        data.first_name || "",
        data.last_name || ""
      );

      // Refresh data
      await fetchData(user.id);

      reset();
      setIsInviteOpen(false);
    } catch (err) {
      setInviteError(err.message || "Failed to send invite");
    } finally {
      setIsInviting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <p className="text-red-600 mb-4">{error}</p>
          <button
            onClick={() => fetchData(user.id)}
            className="bg-primary text-black px-4 py-2 rounded-md hover:bg-yellow-400"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const chartData = selectedPlan
    ? [
        { name: "Used", value: selectedPlan.used_quantity },
        { name: "Available", value: selectedPlan.available_quantity },
      ]
    : [];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <div className="flex items-center space-x-4">
            <button
              onClick={handleLogout}
              className="text-gray-500 hover:text-gray-700 flex items-center gap-2 text-sm font-medium transition-colors"
            >
              <LogOut className="h-4 w-4" /> Logout
            </button>
            <div className="h-8 w-8 bg-primary rounded-full flex items-center justify-center text-black font-bold">
              {user?.first_name?.[0]?.toUpperCase() ||
                user?.email?.[0]?.toUpperCase() ||
                "U"}
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Plans Carousel */}
        <section>
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <CreditCard className="h-5 w-5" /> Your Plans
          </h2>
          {plans.length === 0 ? (
            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 text-center text-gray-500">
              No plans available. Purchase a plan to get started.
            </div>
          ) : (
            <div className="overflow-hidden" ref={emblaRef}>
              <div className="flex gap-4">
                {plans.map((plan) => (
                  <div
                    key={plan.id}
                    className="flex-[0_0_100%] sm:flex-[0_0_50%] md:flex-[0_0_33%] min-w-0 cursor-pointer"
                    onClick={() => setSelectedPlan(plan)}
                  >
                    <motion.div
                      whileHover={{ scale: 1.02 }}
                      className={cn(
                        "p-6 rounded-xl shadow-sm border h-full relative overflow-hidden transition-all duration-200",
                        selectedPlan.id === plan.id
                          ? "bg-yellow-50 border-primary ring-2 ring-primary ring-offset-2"
                          : "bg-white border-gray-100 opacity-80 hover:opacity-100"
                      )}
                    >
                      {selectedPlan.id === plan.id && (
                        <div className="absolute top-0 right-0 bg-primary text-xs font-bold px-3 py-1 rounded-bl-lg shadow-sm">
                          SELECTED
                        </div>
                      )}
                      <h3 className="font-bold text-lg">
                        {plan.plan_title || `Plan ${plan.plan_id}`}
                      </h3>
                      <p className="text-gray-500 text-sm mb-4">
                        SKU: {plan.sku}
                      </p>
                      <div className="flex justify-between items-end">
                        <div>
                          <span className="text-3xl font-bold text-primary">
                            {plan.available_quantity}
                          </span>
                          <span className="text-gray-400 text-sm ml-1">
                            available
                          </span>
                        </div>
                        <div className="text-right">
                          <span className="block text-sm text-gray-500">
                            Total: {plan.total_quantity}
                          </span>
                        </div>
                      </div>
                    </motion.div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Usage Chart */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 lg:col-span-1"
          >
            <h3 className="font-semibold mb-4">
              Usage Overview: {selectedPlan?.plan_title || "No plan selected"}
            </h3>
            {selectedPlan && chartData.length > 0 ? (
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={chartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      fill="#8884d8"
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {chartData.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={COLORS[index % COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-64 w-full flex items-center justify-center text-gray-400">
                No data available
              </div>
            )}
            <div className="flex justify-center gap-4 mt-4 text-sm">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-primary"></div>
                <span>Used</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-gray-200"></div>
                <span>Available</span>
              </div>
            </div>
          </motion.div>

          {/* Invite Manager */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 lg:col-span-2"
          >
            <div className="flex justify-between items-center mb-6">
              <h3 className="font-semibold flex items-center gap-2">
                <Users className="h-5 w-5" /> Team Members
              </h3>

              <Dialog.Root open={isInviteOpen} onOpenChange={setIsInviteOpen}>
                <Dialog.Trigger asChild>
                  <button
                    className="bg-primary text-black px-4 py-2 rounded-md text-sm font-medium hover:bg-yellow-400 transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                    disabled={
                      !selectedPlan || selectedPlan.available_quantity <= 0
                    }
                  >
                    <Send className="h-4 w-4" /> Invite Member
                  </button>
                </Dialog.Trigger>
                <Dialog.Portal>
                  <Dialog.Overlay className="fixed inset-0 bg-black/50 data-[state=open]:animate-overlayShow" />
                  <Dialog.Content className="fixed left-[50%] top-[50%] max-h-[85vh] w-[90vw] max-w-[450px] translate-x-[-50%] translate-y-[-50%] rounded-[6px] bg-white p-[25px] shadow-[hsl(206_22%_7%_/_35%)_0px_10px_38px_-10px,_hsl(206_22%_7%_/_20%)_0px_10px_20px_-15px] focus:outline-none data-[state=open]:animate-contentShow">
                    <Dialog.Title className="text-lg font-bold mb-4">
                      Invite to {selectedPlan?.plan_title || "Plan"}
                    </Dialog.Title>
                    {inviteError && (
                      <div className="bg-red-50 border border-red-200 text-red-600 px-3 py-2 rounded-md text-sm mb-4">
                        {inviteError}
                      </div>
                    )}
                    <form onSubmit={handleSubmit(handleInvite)}>
                      <fieldset className="mb-[15px] flex items-center gap-5">
                        <label
                          className="text-sm font-medium w-[75px]"
                          htmlFor="email"
                        >
                          Email
                        </label>
                        <input
                          className="inline-flex h-[35px] w-full flex-1 items-center justify-center rounded-[4px] px-[10px] text-[15px] leading-none shadow-[0_0_0_1px] outline-none focus:shadow-[0_0_0_2px]"
                          id="email"
                          type="email"
                          placeholder="colleague@company.com"
                          {...register("email", { required: true })}
                        />
                      </fieldset>
                      <div className="mt-[25px] flex justify-end">
                        <button
                          type="submit"
                          disabled={isInviting}
                          className="bg-primary text-black hover:bg-yellow-400 inline-flex h-[35px] items-center justify-center rounded-[4px] px-[15px] font-medium leading-none focus:shadow-[0_0_0_2px] focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {isInviting ? "Sending..." : "Send Invite"}
                        </button>
                      </div>
                      <Dialog.Close asChild>
                        <button
                          className="text-violet11 hover:bg-violet4 focus:shadow-violet7 absolute top-[10px] right-[10px] inline-flex h-[25px] w-[25px] appearance-none items-center justify-center rounded-full focus:shadow-[0_0_0_2px] focus:outline-none"
                          aria-label="Close"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      </Dialog.Close>
                    </form>
                  </Dialog.Content>
                </Dialog.Portal>
              </Dialog.Root>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead>
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Email
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Plan
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {invites.map((invite) => (
                    <tr key={invite.id}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        {invite.recipient_email}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {invite.plan_title}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={cn(
                            "px-2 inline-flex text-xs leading-5 font-semibold rounded-full",
                            invite.status === "sent"
                              ? "bg-green-100 text-green-800"
                              : "bg-gray-100 text-gray-800"
                          )}
                        >
                          {invite.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {invites.length === 0 && (
                    <tr>
                      <td
                        colSpan="3"
                        className="px-6 py-4 text-center text-sm text-gray-500"
                      >
                        No invites sent yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </motion.div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
