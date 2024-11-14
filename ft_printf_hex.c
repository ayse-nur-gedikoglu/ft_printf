/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_hex.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agedikog <gedikoglu_27@icloud.com>         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/11 11:23:31 by agedikog          #+#    #+#             */
/*   Updated: 2024/11/13 18:09:08 by agedikog         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int	ft_smhex(unsigned long long nb)
{
	char	*hex;
	int		i;

	i = 0;
	hex = "0123456789abcdef";
	if (nb >= 16)
		i += ft_smhex(nb / 16);
	i += ft_putchar(hex[nb % 16]);
	return (i);
}

int	ft_bghex(unsigned int nb)
{
	char	*hex;
	int		i;

	i = 0;
	hex = "0123456789ABCDEF";
	if (nb >= 16)
		i += ft_bghex(nb / 16);
	i += ft_putchar(hex[nb % 16]);
	return (i);
}

int	ft_ptr(unsigned long long ptr)
{
	int	i;

	if (!ptr)
		return (write(1, "0x0", 3));
	i = 2;
	ft_putstr("0x");
	i += ft_smhex(ptr);
	return (i);
}
