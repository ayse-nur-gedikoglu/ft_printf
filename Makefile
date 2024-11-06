SRCS	=	ft_print.c ft_puthex.c ft_putchars ft_putnbrs.c

			
OBJS    = $(SRCS:.c=.o)
HDRS    = printf.h
NAME    = printf.a
RM  = rm -rf
GCC = cc
AR  = ar -crs
FLAGS   = -Wall -Wextra -Werror

NO_COLOR = \033[0;39m
GREEN = \033[0;92m
YELLOW = \033[0;93m
BLUE = \033[0;94m
CYAN = \033[0;96m

.c.o:
		@$(GCC) $(FLAGS) -c $< -o $(<:.c=.o)
		@echo "$(YELLOW)Compiling: $< $(DEF_COLOR)"

$(NAME):	$(OBJS) $(HDRS)
			@$(AR) $(NAME) $(OBJS)
			@echo "$(GREEN)libft compiled!$(DEF_COLOR)"

all:	$(NAME)
		
re:		clean fclean all
		@echo "$(GREEN)libft RE compiled!$(DEF_COLOR)"

clean:
		@$(RM) $(OBJS)
		@echo "$(BLUE)libft object files cleaned!$(DEF_COLOR)"


fclean:	clean
		@$(RM) $(NAME)
		@echo "$(CYAN)libft executable files cleaned!$(DEF_COLOR)"
.PHONY:
		all clean fclean re