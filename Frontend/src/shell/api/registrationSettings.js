import axiosInstance from "./axiosInstance";

export const getRegistrationSettings = async () =>
  (await axiosInstance.get("/admin/registration-settings")).data;

export const updateRegistrationSettings = async (body, { reauthCode } = {}) =>
  (
    await axiosInstance.patch(
      "/admin/registration-settings",
      body,
      reauthCode ? { headers: { "X-Reauth-Code": reauthCode } } : {},
    )
  ).data;
