#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    ctrl: Ctrl,
    status: Status,
    data: Data,
    intr: Intr,
    limit0: Limit0,
    limit1: Limit1,
    limit2: Limit2,
    limit3: Limit3,
}
impl RegisterBlock {
    #[doc = "0x00 - ADC Control"]
    #[inline(always)]
    pub const fn ctrl(&self) -> &Ctrl {
        &self.ctrl
    }
    #[doc = "0x04 - ADC Status"]
    #[inline(always)]
    pub const fn status(&self) -> &Status {
        &self.status
    }
    #[doc = "0x08 - ADC Output Data"]
    #[inline(always)]
    pub const fn data(&self) -> &Data {
        &self.data
    }
    #[doc = "0x0c - ADC Interrupt Control Register"]
    #[inline(always)]
    pub const fn intr(&self) -> &Intr {
        &self.intr
    }
    #[doc = "0x10 - ADC Limit"]
    #[inline(always)]
    pub const fn limit0(&self) -> &Limit0 {
        &self.limit0
    }
    #[doc = "0x14 - ADC Limit"]
    #[inline(always)]
    pub const fn limit1(&self) -> &Limit1 {
        &self.limit1
    }
    #[doc = "0x18 - ADC Limit"]
    #[inline(always)]
    pub const fn limit2(&self) -> &Limit2 {
        &self.limit2
    }
    #[doc = "0x1c - ADC Limit"]
    #[inline(always)]
    pub const fn limit3(&self) -> &Limit3 {
        &self.limit3
    }
}
#[doc = "CTRL (rw) register accessor: ADC Control\n\nYou can [`read`](crate::Reg::read) this register and get [`ctrl::R`]. You can [`reset`](crate::Reg::reset), [`write`](crate::Reg::write), [`write_with_zero`](crate::Reg::write_with_zero) this register using [`ctrl::W`]. You can also [`modify`](crate::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrl`]
module"]
#[doc(alias = "CTRL")]
pub type Ctrl = crate::Reg<ctrl::CtrlSpec>;
#[doc = "ADC Control"]
pub mod ctrl;
#[doc = "STATUS (rw) register accessor: ADC Status\n\nYou can [`read`](crate::Reg::read) this register and get [`status::R`]. You can [`reset`](crate::Reg::reset), [`write`](crate::Reg::write), [`write_with_zero`](crate::Reg::write_with_zero) this register using [`status::W`]. You can also [`modify`](crate::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status`]
module"]
#[doc(alias = "STATUS")]
pub type Status = crate::Reg<status::StatusSpec>;
#[doc = "ADC Status"]
pub mod status;
#[doc = "DATA (rw) register accessor: ADC Output Data\n\nYou can [`read`](crate::Reg::read) this register and get [`data::R`]. You can [`reset`](crate::Reg::reset), [`write`](crate::Reg::write), [`write_with_zero`](crate::Reg::write_with_zero) this register using [`data::W`]. You can also [`modify`](crate::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@data`]
module"]
#[doc(alias = "DATA")]
pub type Data = crate::Reg<data::DataSpec>;
#[doc = "ADC Output Data"]
pub mod data;
#[doc = "INTR (rw) register accessor: ADC Interrupt Control Register\n\nYou can [`read`](crate::Reg::read) this register and get [`intr::R`]. You can [`reset`](crate::Reg::reset), [`write`](crate::Reg::write), [`write_with_zero`](crate::Reg::write_with_zero) this register using [`intr::W`]. You can also [`modify`](crate::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@intr`]
module"]
#[doc(alias = "INTR")]
pub type Intr = crate::Reg<intr::IntrSpec>;
#[doc = "ADC Interrupt Control Register"]
pub mod intr;
#[doc = "LIMIT0 (rw) register accessor: ADC Limit\n\nYou can [`read`](crate::Reg::read) this register and get [`limit0::R`]. You can [`reset`](crate::Reg::reset), [`write`](crate::Reg::write), [`write_with_zero`](crate::Reg::write_with_zero) this register using [`limit0::W`]. You can also [`modify`](crate::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@limit0`]
module"]
#[doc(alias = "LIMIT0")]
pub type Limit0 = crate::Reg<limit0::Limit0Spec>;
#[doc = "ADC Limit"]
pub mod limit0;
pub use limit0 as limit1;
pub use limit0 as limit2;
pub use limit0 as limit3;
pub use Limit0 as Limit1;
pub use Limit0 as Limit2;
pub use Limit0 as Limit3;
