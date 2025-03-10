use anchor_lang::prelude::*;

declare_id!("3irsdr81xajUgm3gtFFTBmEPMv8X2eSJaoeCRi51LSS9");

#[program]
pub mod setup {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let solved_account = &mut ctx.accounts.solved_account;
        solved_account.solved = false;
        Ok(())
    }

    pub fn solve(ctx: Context<Solve>) -> Result<()> {
        let solved_account = &mut ctx.accounts.solved_account;
        solved_account.solved = true;
        Ok(())
    }

    pub fn is_solved(ctx: Context<IsSolved>) -> Result<bool> {
        let solved_account = &ctx.accounts.solved_account;
        Ok(solved_account.solved)
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + 1,
    )]
    pub solved_account: Account<'info, SolvedState>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Solve<'info> {
    #[account(mut)]
    pub solved_account: Account<'info, SolvedState>,
}

#[derive(Accounts)]
pub struct IsSolved<'info> {
    pub solved_account: Account<'info, SolvedState>,
}

#[account]
pub struct SolvedState {
    pub solved: bool,
}